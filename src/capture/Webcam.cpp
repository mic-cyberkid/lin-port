#include "Webcam.h"
#ifdef _WIN32
#include <vfw.h>
#include <gdiplus.h>
#include <vector>
#pragma comment(lib, "vfw32.lib")
#pragma comment(lib, "gdiplus.lib")
using namespace Gdiplus;
namespace capture {
    std::vector<BYTE> CaptureWebcamImage() { return {}; }
}
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/videodev2.h>
#include <vector>
#include <cstring>
namespace capture {
    std::vector<uint8_t> CaptureWebcamImage() {
        int fd = open("/dev/video0", O_RDWR);
        if (fd == -1) return {};
        v4l2_capability cap; if (ioctl(fd, VIDIOC_QUERYCAP, &cap) == -1) { close(fd); return {}; }
        v4l2_format fmt; std::memset(&fmt, 0, sizeof(fmt));
        fmt.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        fmt.fmt.pix.width = 640; fmt.fmt.pix.height = 480;
        fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_MJPEG;
        if (ioctl(fd, VIDIOC_S_FMT, &fmt) == -1) { close(fd); return {}; }
        v4l2_requestbuffers req; std::memset(&req, 0, sizeof(req));
        req.count = 1; req.type = V4L2_BUF_TYPE_VIDEO_CAPTURE; req.memory = V4L2_MEMORY_MMAP;
        if (ioctl(fd, VIDIOC_REQBUFS, &req) == -1) { close(fd); return {}; }
        v4l2_buffer buf; std::memset(&buf, 0, sizeof(buf));
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE; buf.memory = V4L2_MEMORY_MMAP; buf.index = 0;
        if (ioctl(fd, VIDIOC_QUERYBUF, &buf) == -1) { close(fd); return {}; }
        void* start = mmap(NULL, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, buf.m.offset);
        if (start == MAP_FAILED) { close(fd); return {}; }
        if (ioctl(fd, VIDIOC_STREAMON, &buf.type) == -1) { munmap(start, buf.length); close(fd); return {}; }
        if (ioctl(fd, VIDIOC_QBUF, &buf) == -1) { ioctl(fd, VIDIOC_STREAMOFF, &buf.type); munmap(start, buf.length); close(fd); return {}; }
        if (ioctl(fd, VIDIOC_DQBUF, &buf) == -1) { ioctl(fd, VIDIOC_STREAMOFF, &buf.type); munmap(start, buf.length); close(fd); return {}; }
        std::vector<uint8_t> res((uint8_t*)start, (uint8_t*)start + buf.bytesused);
        ioctl(fd, VIDIOC_STREAMOFF, &buf.type); munmap(start, buf.length); close(fd); return res;
    }
}
#endif
