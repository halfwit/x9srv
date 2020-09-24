#include <u.h>
#include <libc.h>
#include <draw.h>
#include <cursor.h>
#include <memdraw.h>
#include "devdraw.h"

void rpc_resizeimg(Client*);
void rpc_resizewindow(Client*, Rectangle);
void rpc_setcursor(Client*, Cursor*, Cursor2*);
void rpc_setlabel(Client*, char*);
void rpc_setmouse(Client*, Point);
void rpc_topwin(Client*);
void rpc_bouncemouse(Client*, Mouse);
void rpc_flush(Client*, Rectangle);

void	gfx_abortcompose(Client*);
void	gfx_keystroke(Client*, int);
void	gfx_main(void);
void	gfx_mousetrack(Client*, int, int, int, uint);
void	gfx_replacescreenimage(Client*, Memimage*);
void	gfx_mouseresized(Client*);
void	gfx_started(void);

Memimage *rpc_attach(Client*, char*, char*);
char*	rpc_getsnarf(void);
void	rpc_putsnarf(char*);
void	rpc_shutdown(void);
void	rpc_main(void);


// rpc_gfxdrawlock and rpc_gfxdrawunlock
// are called around drawing operations to lock and unlock
// access to the graphics display, for systems where the
// individual memdraw operations use the graphics display (X11, not macOS).
void rpc_gfxdrawlock(void);
void rpc_gfxdrawunlock(void);

// draw* routines are called on the RPC thread,
// invoked by the RPC server to do pixel pushing.
// No locks are held on entry.
int draw_dataread(Client*, void*, int);
int draw_datawrite(Client*, void*, int);
void draw_initdisplaymemimage(Client*, Memimage*);