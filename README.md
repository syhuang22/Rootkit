# Rootkit Functionality Assignment

This project is an exercise in implementing rootkit functionality with kernel programming, fork/exec to launch child processes, and understanding the types of malicious activities that attackers may attempt against privileged systems programs.

## Table of Contents
- [Overview](#overview)
- [Attack Program](#attack-program)
- [Sneaky Kernel Module](#sneaky-kernel-module)

## Overview

This assignment consists of two main components: the attack program (`sneaky_process.c`) and the sneaky kernel module (`sneaky_mod.c`). 
- The attack program is a small user-level program that performs several malicious actions
- The sneaky kernel module is responsible for implementing the following subversive actions

## Attack Program: sneaky_process.c

The attack program executes the following steps:

1. Prints its own process ID to the screen.
2. Copies the `/etc/passwd` file to `/tmp/passwd` and appends a new user to the end of the `/etc/passwd` file.
3. Loads the sneaky kernel module, passing its process ID to the module.
4. Enters a loop, waiting for keyboard input until receiving the character 'q'.
5. Unloads the sneaky kernel module.
6. Restores the `/etc/passwd` file.

## Sneaky Kernel Module

The sneaky kernel module performs the following subversive actions:

1. Hides the "sneaky_process" executable file from 'ls' and 'find' UNIX commands.
2. Hides the `/proc/<sneaky_process_id>` directory.
3. Hides the modifications made to the `/etc/passwd` file by opening `/tmp/passwd` instead of `/etc/passwd`.
4. Hides the fact that it is an installed kernel module by removing its entry from `/proc/modules`.
