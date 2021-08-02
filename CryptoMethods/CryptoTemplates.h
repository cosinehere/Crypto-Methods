#pragma once

template <typename T>
inline T r_rot(T a, T b) {
    return (a >> b) | (a << ((sizeof(T) >> 3) - b));
}

template <typename T>
inline T l_rot(T a, T b) {
    return (a << b) | (a >> ((sizeof(T) >> 3) - b));
}
