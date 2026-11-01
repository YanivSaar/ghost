//! Process-tree target. In-kernel fork tracking adds children to PID_SET so no
//! short-lived fork escapes the filter; mirrors parent->child edges. TODO.
