#include <string_view>
#include <filesystem>
#include <syncstream>
#include <iostream>
#include <charconv>
#include <cstring>
#include <fstream>
#include <thread>
#include <utility>
#include <vector>
#include <future>
#include <format>
#include <queue>

#include "ctpl.h"

#include <windows.h>

#include <Python.h>


namespace fs = std::filesystem;


using digest_t = long long;


template<typename ...Args>
void print_stream(std::ostream& os, std::string_view fmt, Args&&... args)
{
    std::osyncstream(os) << std::vformat(fmt, std::make_format_args(args...));
}

template<typename ...Args>
inline void print(std::string_view fmt, Args&&... args)
{
    print_stream(std::cout, fmt, args...);
}

template<typename ...Args>
inline void printerr(std::string_view fmt, Args&&... args)
{
    print_stream(std::cerr, fmt, args...);
}


class params
{
public:
    static void parse(int argc, char** argv)
    {
        tokens.reserve(argc - 1);

        for (size_t i = 1; i < static_cast<size_t>(argc); ++i)
            tokens.emplace_back(argv[i]);

        program_name = argv[0];
    }

    static std::string_view param_of(std::string_view option, std::string_view default_value = {})
    {
        const auto beg = std::cbegin(tokens);
        const auto end = std::cend(tokens);

        auto itr = std::find(beg, end, option);

        if (itr != end && ++itr != end)
            return *itr;

        return default_value;
    }

    static unsigned int iparam_of(std::string_view option, std::from_chars_result& result)
    {
        const auto param = param_of(option);

        if (param.empty())
            return 0;

        const char* beg = std::data(param);
        const char* end = beg + std::size(param);
        unsigned int iparam {};

        result = std::from_chars(beg, end, iparam);

        return iparam;
    }

    static bool has_option(std::string_view option)
    {
        const auto beg = std::begin(tokens);
        const auto end = std::end(tokens);

        return std::find(beg, end, option) != end;
    }

    static bool has_value(std::string_view option)
    {
        const std::string_view value = param_of(option);

        return !value.empty();
    }

    static void help()
    {
        const std::string_view usage =
                "Usage: {} -d <input directory> -f <input file> -o <output file> -t <thread counts> [-r] [-of (lazy|json)] -p <python file>\n"
                "\t-o  optional output file, default is exported.txt\n"
                "\t-r  optional recursive flag\n"
                "\t-e  skip file that don't have .DLL/.dll extension\n"
                "\t-p  path to a python file containing the hashing function to create a hashtable\n"
                "\t-H  name of the python hashing function to execute, default is \"digest\"\n"
                "\t-of output format, default is lazy\n"
                "The program will not run if both -d and -f arguments are not given\n";

        print(usage, program_name);
    }

private:
    inline static std::vector<std::string_view> tokens;
    inline static std::string_view program_name;
};



namespace py
{
    enum class semantic
    {
        owning,
        shared
    };

    class PyObject_Ref
    {
        // NOTE: Py_XINCREF/Py_XDECREF already checks for nullptr

    public:
        PyObject_Ref() : handle(nullptr) {}

        PyObject_Ref(PyObject* ptr, semantic ownership = semantic::owning) : handle(ptr)
        {
            if (ownership == semantic::shared)
                Py_XINCREF(handle);
        }

        ~PyObject_Ref() { Py_XDECREF(handle); }

        PyObject_Ref(const PyObject_Ref& right) : handle(right.handle) { Py_XINCREF(handle); }
        PyObject_Ref(PyObject_Ref&& right) : handle(nullptr)
        {
            std::swap(handle, right.handle);
        }

        PyObject_Ref& operator=(const PyObject_Ref& right) noexcept
        {
            PyObject_Ref tmp(right);
            std::swap(handle, tmp.handle);
            return *this;
        }

        PyObject_Ref& operator=(PyObject_Ref&& right) noexcept
        {
            std::swap(handle, right.handle);
            return *this;
        }

        PyObject_Ref& operator=(PyObject* ptr) noexcept
        {
            handle = ptr;
            return *this;
        }

        operator bool()      const { return handle != nullptr; }
        operator PyObject*() const { return handle; }

    private:
        PyObject* handle;
    };


    void PySys_AppendPath(std::string_view modules_directory)
    {
        PyObject_Ref msys(PyImport_ImportModule("sys"));

        if (!msys)
            return;

        PyObject_Ref path(PyObject_GetAttrString(msys, "path"));

        if (!path)
            return;

        PyList_Append(path, PyUnicode_FromString(modules_directory.data()));
    }

    class hash_function
    {
    public:
        explicit hash_function(PyObject_Ref callable)
            : hasher(std::move(callable))
        {}

        ~hash_function() = default;

        explicit operator bool() const
        {
            return hasher && PyCallable_Check(hasher);
        }

        digest_t operator()(std::string_view input) const
        {
            // TODO: different errcode
            if (!*this)
                return 0;

            PyObject_Ref pyarg(PyTuple_New(1));
            PyObject_Ref value(PyUnicode_FromString(input.data()), semantic::shared);

            if (!value)
            {
                printerr("Error building hash function argument for value {}\n", input);
                PyErr_Print();
                return 0;
            }

            PyTuple_SetItem(pyarg, 0, value);

            PyObject_Ref digest(PyObject_CallObject(hasher, pyarg));

            if (!digest)
            {
                printerr("Error building return value for hash function\n");
                PyErr_Print();
                return 0;
            }

            return static_cast<digest_t>(PyLong_AsLongLong(digest));
        }

    private:
        PyObject_Ref hasher;
    };

    //  wrapper for the python context
    class context
    {
        class raii_context
        {
        public:
            raii_context()  { Py_Initialize(); }
            ~raii_context() { Py_Finalize();   }
        };

        static raii_context raii_instance;

        inline static PyObject_Ref imported_module;
        inline static PyObject_Ref imported_function;

    public:
        static bool import_module(std::string_view module_path_)
        {
            // a module or function was already imported
            if (imported_module || imported_function)
                return false;

            fs::path module_path = module_path_;
            const std::string modname = module_path.filename().replace_extension().string();
            const std::string moddir  = module_path.remove_filename().string();

            PySys_AppendPath(moddir);

            imported_module = PyImport_ImportModule(modname.data());

            if (!imported_module)
            {
                PyErr_Print();
                return false;
            }

            return true;
        }

        static bool resolve_function(std::string_view function_name)
        {
            // module could not be imported or a function was already imported
            if (!imported_module || imported_function)
                return false;

            PyObject_Ref symbol(PyObject_GetAttrString(imported_module, function_name.data()));

            if (!symbol)
            {
                PyErr_Print();
                return false;
            }

            if (!PyCallable_Check(symbol))
            {
                printerr("Symbol {} is not a function\n", function_name);
                return false;
            }

            imported_function = symbol;

            return true;
        }

        static PyObject_Ref get_imported_function()
        {
            return imported_function;
        }
    };

    context::raii_context context::raii_instance {};

    class gil_guard
    {
    public:
        gil_guard()
        {
            state = PyGILState_Ensure();
        }

        ~gil_guard()
        {
            PyGILState_Release(state);
        }

    private:
        PyGILState_STATE state;
    };

    class enable_threads
    {
    public:
        enable_threads()
        {
            state = PyEval_SaveThread();
        }

        ~enable_threads()
        {
            PyEval_RestoreThread(state);
        }

    private:
        PyThreadState* state;
    };
}


namespace exports
{
    struct hash_pair
    {
        digest_t hash;
        std::string symbol;
    };

    struct result
    {
        std::string module;
        std::vector<std::string> exported_symbols;
        std::vector<hash_pair> hashtable;

        bool ok {};
    };

    size_t read_threads_count(size_t max_tasks)
    {
        std::from_chars_result conv_result {};

        auto threads_count = params::iparam_of("-t", conv_result);

        const auto [ptr, ec] = conv_result;

        if (ec == std::errc::invalid_argument && std::strcmp(ptr, "max") == 0)
            threads_count = std::thread::hardware_concurrency();

        if (threads_count == 0)
        {
            std::cerr << "Could not read threads count parameter (-t). Defaulting to a single thread\n";
            threads_count = 1;
        }

        if (threads_count > max_tasks)
            threads_count = max_tasks;

        return threads_count;
    }

    std::queue<fs::path> enumerate_files(std::string_view path_dir, std::string_view path_file)
    {
        std::queue<fs::path> files;

        auto queue_entries = [&](const auto& walker) -> void
        {
            for (auto& entry : walker)
            {
                auto path = entry.path();

                if (params::has_option("-e") && path.extension() != ".DLL" && path.extension() != ".dll")
                    continue;

                files.push(std::move(path));
            }
        };

        // We never use it, but this prevents directory iterator from throwing
        std::error_code ec {};

        if (params::has_option("-r"))
        {
            const fs::recursive_directory_iterator walker(path_dir, ec);
            queue_entries(walker);
        } else
        {
            const fs::directory_iterator walker(path_dir, ec);
            queue_entries(walker);
        }

        if (!path_file.empty() && fs::exists(path_file))
			files.push(path_file);

        if (files.empty())
            std::cerr << "Could not enumerate files from provided arguments, no such directory or no files to process\n";

        return files;
    }

    std::vector<uint8_t> read_data(const fs::path& path, bool& err)
    {
        std::ifstream stream(path, std::ios::binary | std::ios::ate);

        const auto size = stream.tellg();

        stream.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer;
        buffer.reserve(size);

        err = stream.read(reinterpret_cast<char*>(buffer.data()), size).fail();

        return buffer;
    }

    PIMAGE_SECTION_HEADER section_from_rva(uint64_t rva, PIMAGE_NT_HEADERS64 nt_hdrs)
    {
        if (rva == 0 || nt_hdrs == nullptr)
            return nullptr;

        const auto section_count = nt_hdrs->FileHeader.NumberOfSections;
        auto section_hdr = IMAGE_FIRST_SECTION(nt_hdrs);

        // loop through sections
        for (size_t i = 0; i < section_count && section_hdr != nullptr; ++i)
        {
            const auto beg = section_hdr->VirtualAddress;
            const auto end = section_hdr->VirtualAddress + section_hdr->Misc.VirtualSize;

            // check if the address is inside the range of the section
            if (rva >= beg && rva <= end)
                return section_hdr;

            ++section_hdr;
        }

        return nullptr;
    }

    uint64_t rva2offset(uint64_t rva, PIMAGE_NT_HEADERS64 nt_hdrs)
    {
        // Converts a relative virtual address to an offset on the disk image

        // determine in which section RVA points
        PIMAGE_SECTION_HEADER section_hdr = section_from_rva(rva, nt_hdrs);

        if (section_hdr == nullptr)
            return 0;

        const size_t in_sct_offset = rva - section_hdr->VirtualAddress;

        return section_hdr->PointerToRawData + in_sct_offset;
    }

    PIMAGE_DOS_HEADER read_dos_header(const uint8_t* pe_base)
    {
        if (pe_base == nullptr)
            return nullptr;

        const auto header = (PIMAGE_DOS_HEADER)pe_base;

        if (header->e_magic != IMAGE_DOS_SIGNATURE)
        {
            printerr("Dropping file because of wrong DOS header signature\n");
            return nullptr;
        }

        return header;
    }

    PIMAGE_NT_HEADERS64 read_nt_headers(const uint8_t* pe_base)
    {
        if (pe_base == nullptr)
            return nullptr;

        const auto header = read_dos_header(pe_base);
        const auto nthdrs = (PIMAGE_NT_HEADERS64)(pe_base + header->e_lfanew);

        if (nthdrs->Signature != IMAGE_NT_SIGNATURE)
        {
            printerr("Dropping file because of wrong PE header signature");
            return nullptr;
        }

        if (!(nthdrs->FileHeader.Characteristics & IMAGE_FILE_DLL))
        {
            printerr("Dropping file because of wrong file header characteristics (!IMAGE_FILE_DLL)");
            return nullptr;
        }

        return nthdrs;
    }

    PIMAGE_OPTIONAL_HEADER64 read_optional_header(const uint8_t* pe_base)
    {
        PIMAGE_NT_HEADERS64 nthdrs = read_nt_headers(pe_base);

        if (nthdrs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            printerr("Dropping file because of wrong optional header signature");
            return nullptr;
        }

        return &nthdrs->OptionalHeader;
    }

    PIMAGE_EXPORT_DIRECTORY read_export_directory(const uint8_t* pe_base)
    {
        PIMAGE_OPTIONAL_HEADER64 opt_header = read_optional_header(pe_base);
        IMAGE_DATA_DIRECTORY& export_descriptor = opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (export_descriptor.Size == 0 || export_descriptor.VirtualAddress == 0)
            return nullptr;

        PIMAGE_NT_HEADERS64 nthdrs = read_nt_headers(pe_base);

        return (PIMAGE_EXPORT_DIRECTORY)(pe_base + rva2offset(export_descriptor.VirtualAddress, nthdrs));
    }

    bool enumerate_exports(const std::vector<uint8_t>& data, std::vector<std::string>& exports)
    {
        // TODO: check for nullptr on function returns
        // TODO: use a string view to check for out-of-bounds
        const uint8_t* pe_base = data.data();

        PIMAGE_NT_HEADERS64 nthdrs = read_nt_headers(pe_base);
        PIMAGE_EXPORT_DIRECTORY export_directory = read_export_directory(pe_base);

        if (export_directory == nullptr)
            return false;

        const auto names = reinterpret_cast<const DWORD*>(pe_base + rva2offset(export_directory->AddressOfNames, nthdrs));

        exports.reserve(export_directory->NumberOfNames);

        for (size_t i = 0; i < export_directory->NumberOfNames; ++i)
        {
            const auto function_name = reinterpret_cast<const char *>(pe_base + rva2offset(names[i], nthdrs));
            exports.emplace_back(function_name);
        }

        return true;
    }

    std::vector<hash_pair> make_hashtable(std::vector<std::string>& symbols)
    {
        std::vector<hash_pair> hashtable;
        hashtable.reserve(symbols.size());

        py::gil_guard lock_guard;

        py::hash_function hasher(py::context::get_imported_function());

        if (hasher)
            for (auto& symbol: symbols)
                hashtable.push_back( { hasher(symbol), std::move(symbol) } );

        return hashtable;
    }

    result process_file(size_t tid [[maybe_unused]], const fs::path& path)
    {
        result result;

        print("Processing: {}\n", path.string());

        bool err {};
        const std::vector<uint8_t> data = read_data(path, err);

        if (err)
        {
            printerr("Could not read data from file {}\n", path.string());
            result.ok = false;
            return {};
        }

        result.module = path.filename().string();

        if (!enumerate_exports(data, result.exported_symbols))
        {
            result.exported_symbols.clear();
            result.ok = false;

            printerr("Format error, {} processing aborted\n", path.string());
            return result;
        }

        result.ok = true;

        if (!params::has_value("-p"))
            return result;

        result.hashtable = make_hashtable(result.exported_symbols);

        return result;
    }

    enum class output_fmt
    {
        lazy,
        json
    };

    class writer
    {
    public:
        explicit writer(std::string_view output_path_, output_fmt format_)
            : output_path(output_path_),
              format(format_),
              ostream(output_path.data())
        {
            if (!fail() && format == output_fmt::json)
                ostream << "[\n";
        }

        ~writer()
        {
            if (!fail() && format == output_fmt::json)
                ostream << "\n]";
        }

        [[nodiscard]]
        bool fail() const
        {
            return ostream.fail();
        }

        void write(const exports::result& data) {
            if (fail())
                return;

            const auto &[module, symbols, hashtable, _] = data;

            if (format == output_fmt::lazy) {
                if (hashtable.empty())
                    for (const auto &sym: symbols)
                        print_stream(ostream, "{} {}\n", module, sym);
                else
                    for (const auto &[hash, sym]: hashtable)
                        print_stream(ostream, "{} {:#x} {}\n", module, hash, sym);

                return;
            }

            if (!first_block)
                ostream << ",\n";
            else
                first_block = false;

            constexpr std::string_view fmt =
                    "\t{{\n"
                    "\t\t\"library\": \"{}\",\n";

            ostream << std::vformat(fmt, std::make_format_args(module));

            if (hashtable.empty())
            {
                ostream << "\t\t\"exports\": [\n";
                for (size_t i = 0; i < symbols.size(); ++i)
                {
                    ostream << "\t\t\t" << std::quoted(symbols[i]);

                    if (i != symbols.size() - 1)
                        ostream << ",";

                    ostream << '\n';
                }
            }
            else
            {
                ostream << "\t\t\"hashed\": {\n";
                for (size_t i = 0; i < hashtable.size(); ++i)
                {
                    const auto& [hash, symbol] = hashtable[i];
                    ostream << std::vformat("\t\t\t\"{:#x}\": \"{}\"", std::make_format_args(hash, symbol));

                    if (i != symbols.size() - 1)
                        ostream << ",";

                    ostream << '\n';
                }
            }

            ostream << "\t\t]\n\t}";
        }

    private:
        std::string_view output_path;
        output_fmt format;
        std::ofstream ostream;
        bool first_block = true;
    };

    output_fmt write_format()
    {
        if (params::param_of("-of") == "json")
            return exports::output_fmt::json;

        return exports::output_fmt::lazy;
    }

    bool write_results(std::vector<std::future<result>>& futures)
    {
        writer writer(
            params::param_of("-o", "exported.txt"),
            write_format()
        );

        if (writer.fail())
        {
            printerr("Failed to open output stream. Aborting\n");
            return false;
        }

        std::vector<exports::result> results;

        for (auto& future : futures)
        {
            results.push_back(std::move(future.get()));
            const auto& result = results.back();

            if (result.ok)
            {
                writer.write(result);
                print("Processed {}\n", result.module);
            }
        }

        return true;
    }
}


int main(int argc, char** argv)
{
    params::parse(argc, argv);

    if (params::has_option("-h") || (!params::has_value("-d") && !params::has_value("-f")))
    {
        params::help();
        return EXIT_SUCCESS;
    }

    auto fpath_queue = exports::enumerate_files(
                            params::param_of("-d"),
                            params::param_of("-f")
                       );

    if (fpath_queue.empty())
        return EXIT_FAILURE;

    const size_t total_tasks = fpath_queue.size();
    const size_t threads_count = exports::read_threads_count(total_tasks);

    ctpl::thread_pool pool(threads_count);
    std::vector<std::future<exports::result>> futures;

    if (params::has_value("-p"))
    {
        const auto python_file = params::param_of("-p");
        const auto python_func = params::param_of("-H", "digest");

        if (!py::context::import_module(python_file) || !py::context::resolve_function(python_func))
            printerr("Could not import function {} from python file {}\n", python_func, python_file);
    }

    py::enable_threads et;

    // create workers
    while (!fpath_queue.empty())
    {
        fs::path file = fpath_queue.front();
        fpath_queue.pop();

        // add a new task
        futures.push_back(
            pool.push(exports::process_file, std::move(file))
        );
    }

    return exports::write_results(futures) ? EXIT_SUCCESS : EXIT_FAILURE;
}
