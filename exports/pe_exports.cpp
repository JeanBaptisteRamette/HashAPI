#include <string_view>
#include <filesystem>
#include <iostream>
#include <charconv>
#include <cstring>
#include <fstream>
#include <thread>
#include <vector>
#include <future>
#include <format>
#include <queue>

#include "ctpl.h"

#include <windows.h>


namespace fs = std::filesystem;


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

    static std::string_view param_of(std::string_view option)
    {
        const auto beg = std::cbegin(tokens);
        const auto end = std::cend(tokens);

        auto itr = std::find(beg, end, option);

        if (itr != end && ++itr != end)
            return *itr;

        return {};
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

    static void help()
    {
        const std::string_view usage =
                "Usage: {} -d <input directory> -f <input file> -o <output file> -t <thread counts> [-r] [-of (lazy|json)]\n"
                "\t-o optional output file, default is exported.txt\n"
                "\t-r optional recursive flag\n"
                "\t-v skip file that don't have .DLL/.dll extension\n"
                "\t-of output format, default is lazy\n"
                "The program will not run if both -d and -f arguments are not given\n";

        std::cout << std::vformat(usage, std::make_format_args(program_name));
    }

private:
    inline static std::vector<std::string_view> tokens;
    inline static std::string_view program_name;
};


namespace detail::concurrency
{
    std::mutex cout_mutex;
}


template<typename ...Args>
void print(std::string_view fmt, Args&&... args)
{
    std::lock_guard lock(detail::concurrency::cout_mutex);

    std::cout << std::vformat(fmt, std::make_format_args(args...));
}


namespace exports
{
    constexpr uint16_t SIG_DOS = 0x5A4D;
    constexpr uint16_t SIG_PE  = 0x4550;

    struct result
    {
        std::string module;
        std::vector<std::string> exported_symbols;
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
            const fs::recursive_directory_iterator walker(path_dir);
            queue_entries(walker);
        } else
        {
            const fs::directory_iterator walker(path_dir, ec);
            queue_entries(walker);
        }

        if (!path_file.empty() && fs::exists(path_file))
			files.push(path_file);

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
            print("Dropping file because of wrong DOS header signature");
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
            print("Dropping file because of wrong PE header signature");
            return nullptr;
        }

        if (!(nthdrs->FileHeader.Characteristics & IMAGE_FILE_DLL))
        {
            print("Dropping file because of wrong file header characteristics (!IMAGE_FILE_DLL)");
            return nullptr;
        }

        return nthdrs;
    }

    PIMAGE_OPTIONAL_HEADER64 read_optional_header(const uint8_t* pe_base)
    {
        PIMAGE_NT_HEADERS64 nthdrs = read_nt_headers(pe_base);

        if (nthdrs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            print("Dropping file because of wrong optional header signature");
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

    bool process_file_internal(const std::vector<uint8_t>& data, std::vector<std::string>& exports)
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

    result process_file(int id, const fs::path& path)
    {
        result result;

        print("Processing: {}\n", path.string());

        bool err {};
        const std::vector<uint8_t> data = read_data(path, err);

        if (err)
        {
            print("Could not read data from file {}\n", path.string());
            result.ok = false;
            return {};
        }

        result.module = path.filename().string();

        if (!process_file_internal(data, result.exported_symbols))
        {
            result.exported_symbols.clear();
            result.ok = false;

            print("{} processing aborted\n", path.string());
            return result;
        }

        print("Processed: {}\n", path.string());

        result.ok = true;

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

        void write(const exports::result& data)
        {
            if (fail())
                return;

            const auto& [module, exports, _] = data;

            if (format == output_fmt::lazy)
            {
                for (const auto& exported : exports)
                    ostream << module << ' ' << exported << '\n';

                return;
            }

            if (!first_block)
                ostream << ",\n";
            else
                first_block = false;


            // JSON output
            constexpr std::string_view fmt =
            "\t{{\n"
            "\t\t\"library\": \"{}\"\n"
            "\t\t\"exports\": [\n";

            ostream << std::vformat(fmt, std::make_format_args(module));

            for (size_t i = 0; i < exports.size(); ++i)
            {
                ostream << "\t\t\t" << std::quoted(exports[i]);

                if (i != exports.size() - 1)
                    ostream << ",";

                ostream << '\n';
            }

            ostream << "\t\t]\n\t}";
        }

    private:
        std::string_view output_path;
        output_fmt format;
        std::ofstream ostream;
        bool first_block = true;
    };
}


int main(int argc, char** argv)
{
    params::parse(argc, argv);

    if (params::has_option("-h"))
    {
        params::help();
        return EXIT_SUCCESS;
    }

    const auto path_dir  = params::param_of("-d");
    const auto path_file = params::param_of("-f");

    if (path_dir.empty() && path_file.empty())
    {
        params::help();
        return EXIT_FAILURE;
    }

    auto fpath_queue = exports::enumerate_files(path_dir, path_file);

    if (fpath_queue.empty())
    {
        std::cerr << "Could not enumerate files from provided arguments" << '\n';
        return EXIT_FAILURE;
    }

    const auto total_tasks = fpath_queue.size();
    const auto threads_count = exports::read_threads_count(total_tasks);

    ctpl::thread_pool pool(threads_count);
    std::vector<std::future<exports::result>> results;

    // NOTE: queue does not need to be thread-safe.
    while (!fpath_queue.empty())
    {
        const auto file = fpath_queue.front();
        fpath_queue.pop();

        results.push_back(
            pool.push(exports::process_file, file)
        );
    }

    const auto write_format = []() -> exports::output_fmt
    {
        if (params::param_of("-of") == "json")
            return exports::output_fmt::json;

        return exports::output_fmt::lazy;
    }();

    const auto output_path = []() -> std::string_view
    {
        if (!params::has_option("-o"))
            return "exported.txt";

        return params::param_of("-o");
    }();

    exports::writer writer(output_path, write_format);

    if (writer.fail())
    {
        pool.stop();
        return EXIT_FAILURE;
    }

    for (auto& future : results)
    {
        exports::result result = future.get();

        if (result.ok)
            writer.write(result);
    }

	return EXIT_SUCCESS;
}
