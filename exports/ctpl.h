/*********************************************************
*
*  Copyright (C) 2014 by Vitaliy Vitsentiy
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*
*********************************************************/


#ifndef ctpl_stl_thread_pool_H
#define ctpl_stl_thread_pool_H

#include <functional>
#include <memory>
#include <thread>
#include <atomic>
#include <vector>
#include <memory>
#include <exception>
#include <future>
#include <mutex>
#include <queue>



// thread pool to run user's functors with signature
//      ret func(int id, other_params)
// where id is the index of the thread that runs the functor
// ret is some return type


namespace ctpl 
{
    namespace detail 
    {
        template <typename T>
        class threadsafe_queue 
        {
        public:
            void push(const T& value)
            {
                std::lock_guard lock(mutex);
                q.push(value);
            }
            
            // deletes the retrieved element, do not use for non integral types
            bool pop(T& v) 
            {
                std::lock_guard lock(mutex);

                if (q.empty())
                    return false;

                v = q.front();
                q.pop();
                return true;
            }
            
            [[nodiscard]]
            bool empty() const
            {
                std::lock_guard lock(mutex);
                return q.empty();
            }
            
        private:
            std::queue<T> q;
            std::mutex mutex;
        };
    }

    class thread_pool 
    {
    public:
        thread_pool(const thread_pool&) = delete;
        thread_pool(thread_pool&&) = delete;
        thread_pool& operator=(const thread_pool&) = delete;
        thread_pool& operator=(thread_pool&&) = delete;

        thread_pool() = default;

        explicit thread_pool(size_t threads_count)
        {
            resize(threads_count);
        }

        // the destructor waits for all the functions in the threadsafe_queue to be finished
        ~thread_pool() 
        {
            stop(true);
        }

        // get the number of running threads in the pool
        size_t size() const
        {
            return threads.size();
        }

        // number of idle threads
        size_t n_idle() const
        {
            return nWaiting; 
        }
        
        std::thread& get_thread(size_t i)
        {
            return *threads[i]; 
        }

        // change the number of threads in the pool
        // should be called from one thread, otherwise be careful to not interleave, also with stop()
        // threads_count must be >= 0
        void resize(size_t threads_count)
        {
            if (!isStop && !isDone) 
            {
                const size_t prev_thd_count = threads.size();

                // if the number of threads is increased
                if (prev_thd_count <= threads_count)
                {
                    threads.resize(threads_count);
                    flags.resize(threads_count);

                    for (size_t i = prev_thd_count; i < threads_count; ++i)
                    {
                        flags[i] = std::make_shared<std::atomic<bool>>(false);
                        set_thread(i);
                    }
                }
                else
                {  // the number of threads is decreased
                    for (size_t i = prev_thd_count - 1; i >= threads_count; --i)
                    {
                        *flags[i] = true;  // this thread will finish
                        threads[i]->detach();
                    }
                    
                    {
                        // stop the detached threads that were waiting
                        std::unique_lock<std::mutex> lock(mutex);
                        cv.notify_all();
                    }
                    
                    threads.resize(threads_count);  // safe to delete because the threads are detached
                    flags.resize(threads_count);  // safe to delete because the threads have copies of shared_ptr of the flags, not originals
                }
            }
        }

        // empty the threadsafe_queue
        void clear_queue() 
        {
            std::function<void(size_t id)>* _f = nullptr;
            
            while (q.pop(_f))
                delete _f; // empty the threadsafe_queue
        }

        // pops a functional wrapper to the original function
        std::function<void(size_t)> pop()
        {
            std::function<void(size_t id)> * _f = nullptr;
            q.pop(_f);
            std::unique_ptr<std::function<void(size_t id)>> func(_f); // at return, delete the function even if an exception occurred
            std::function<void(size_t)> f;
            
            if (_f)
                f = *_f;
            
            return f;
        }

        // wait for all computing threads to finish and stop all threads
        // may be called asynchronously to not pause the calling thread while waiting
        // if isWait == true, all the functions in the threadsafe_queue are run, otherwise the threadsafe_queue is cleared without running the functions
        void stop(bool isWait = false) 
        {
            if (!isWait) 
            {
                if (isStop)
                    return;
                
                isStop = true;
                
                for (size_t i = 0, n = size(); i < n; ++i)
                    *flags[i] = true;  // command the threads to stop
                
                clear_queue();  // empty the threadsafe_queue
            }
            else
            {
                if (isDone || isStop)
                    return;
                
                isDone = true;  // give the waiting threads a command to finish
            }
            
            {
                std::unique_lock<std::mutex> lock(mutex);
                cv.notify_all();  // stop all waiting threads
            }

            // wait for the computing threads to finish
            for (auto& thread : threads)
            {  
                if (thread->joinable())
                    thread->join();
            }
            
            // if there were no threads in the pool but some functors in the threadsafe_queue, the functors are not deleted by the threads
            // therefore delete them here
            clear_queue();
            threads.clear();
            flags.clear();
        }

        template<typename F, typename... Rest>
        auto push(F&& f, Rest&&... rest) -> std::future<decltype(f(0, rest...))>
        {
            auto pck = std::make_shared<std::packaged_task<decltype(f(0, rest...))(size_t)>>(
                std::bind(std::forward<F>(f), std::placeholders::_1, std::forward<Rest>(rest)...)
                );
            
            auto _f = new std::function<void(size_t id)>(
                [pck](size_t id)
                {
                    (*pck)(id);
                }
            );
            
            q.push(_f);
            std::unique_lock<std::mutex> lock(mutex);
            cv.notify_one();
            return pck->get_future();
        }

        // run the user's function that excepts argument int - id of the running thread. returned value is templatized
        // operator returns std::future, where the user can get the result and rethrow the catched exceptins
        template<typename F>
        auto push(F && f) -> std::future<decltype(f(0))>
        {
            auto pck = std::make_shared<std::packaged_task<decltype(f(0))(size_t)>>(std::forward<F>(f));
            auto _f = new std::function<void(size_t id)>(
                [pck](size_t id)
                {
                    (*pck)(id);
                }
            );
            
            q.push(_f);
            std::unique_lock<std::mutex> lock(mutex);
            cv.notify_one();
            return pck->get_future();
        }


    private:
        void set_thread(size_t i)
        {
            std::shared_ptr<std::atomic<bool>> flag(flags[i]); // a copy of the shared ptr to the flag
            auto f = [this, i, flag/* a copy of the shared ptr to the flag */]() 
            {
                std::atomic<bool>& _flag = *flag;
                std::function<void(size_t id)> * _f;
                bool isPop = q.pop(_f);
                
                while (true) 
                {
                    while (isPop)
                    {  // if there is anything in the threadsafe_queue
                        std::unique_ptr<std::function<void(size_t id)>> func(_f); // at return, delete the function even if an exception occurred
                        (*_f)(i);
                        
                        if (_flag)
                            return;  // the thread is wanted to stop, return even if the threadsafe_queue is not empty yet
                        else
                            isPop = q.pop(_f);
                    }
                    
                    // the threadsafe_queue is empty here, wait for the next command
                    std::unique_lock<std::mutex> lock(mutex);
                    ++nWaiting;
                    cv.wait(lock, [this, &_f, &isPop, &_flag](){ isPop = q.pop(_f); return isPop || isDone || _flag; });
                    --nWaiting;
                    if (!isPop)
                        return;  // if the threadsafe_queue is empty and isDone == true or *flag then return
                }
            };

            threads[i] = std::make_unique<std::thread>(f);
        }

        std::vector<std::unique_ptr<std::thread>> threads;
        std::vector<std::shared_ptr<std::atomic<bool>>> flags;
        detail::threadsafe_queue<std::function<void(size_t id)> *> q;
        std::atomic<bool> isDone  {};
        std::atomic<bool> isStop  {};
        std::atomic<int> nWaiting {};  // how many threads are waiting

        std::mutex mutex;
        std::condition_variable cv;
    };
}

#endif // ctpl_stl_thread_pool_H
