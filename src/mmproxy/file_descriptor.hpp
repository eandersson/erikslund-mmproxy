#pragma once
// Own one Linux file descriptor: a socket, pipe end, epoll instance or event counter.

namespace erikslund::mmproxy {

class FileDescriptor {
public:
    FileDescriptor() = default;
    explicit FileDescriptor(int descriptor) noexcept;
    ~FileDescriptor();
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept;
    FileDescriptor& operator=(FileDescriptor&& other) noexcept;

    [[nodiscard]] int get() const noexcept;
    explicit operator bool() const noexcept;
    void reset() noexcept;

private:
    int descriptor_ = -1;
};

} // namespace erikslund::mmproxy
