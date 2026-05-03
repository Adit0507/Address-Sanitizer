#pragma once

#ifndef ASAN_MSVC_HOOKS_H
#define ASAN_MSVC_HOOKS_H

int asan_call_depth();  //current instrumented call depth
void asan_reset_call_depth();   //rests depthcounter

#endif