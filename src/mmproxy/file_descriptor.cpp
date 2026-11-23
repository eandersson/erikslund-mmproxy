#include "mmproxy/file_descriptor.hpp"

#include <utility>

#include <unistd.h>

namespace erikslund::mmproxy {

FileDescriptor::FileDescriptor(int descriptor) noexcept : descriptor_(descriptor) {}

FileDescriptor::~FileDescriptor() {
    reset();
}

FileDescriptor::FileDescriptor(FileDescriptor&& other) noexcept
    : descriptor_(std::exchange(other.descriptor_, -1)) {}

FileDescriptor& FileDescriptor::operator=(FileDescriptor&& other) noexcept {
    if (this != &other) {
        reset();
        descriptor_ = std::exchange(other.descriptor_, -1);
    }
    return *this;
}

int FileDescriptor::get() const noexcept {
    return descriptor_;
}

FileDescriptor::operator bool() const noexcept {
    return descriptor_ >= 0;
}

void FileDescriptor::reset() noexcept {
    if (descriptor_ >= 0) {
        ::close(descriptor_);
        descriptor_ = -1;
    }
}

} // namespace erikslund::mmproxy
