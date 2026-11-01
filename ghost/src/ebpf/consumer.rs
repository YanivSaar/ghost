//! Blocking ring-buffer drain (epoll). Zero-copy decode of each record to a
//! typed &Event, tee raw to the session writer, then fold into mode state.
//! Reads + surfaces the kernel drop counter (§6). TODO.
