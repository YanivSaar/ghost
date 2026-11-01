//! Render loop + input. Reads an immutable view-model under a brief read lock;
//! non-blocking key/mouse poll on the same loop. Probes mouse capability at
//! startup (crossterm EnableMouseCapture / SGR 1006 / terminfo kmous) and lights
//! up clickable tabs, rows, buttons, wheel, and the replay scrubber only when
//! supported — never a mouse-only action. A Drop guard restores the terminal
//! (leave raw mode, show cursor, disable mouse capture) on panic/signal. TODO.
