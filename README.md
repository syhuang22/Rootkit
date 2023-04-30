# Rootkit Functionality Assignment

This project is an exercise in implementing rootkit functionality with kernel programming, fork/exec to launch child processes, and understanding the types of malicious activities that attackers may attempt against privileged systems programs.

## Table of Contents
- [Overview](#overview)
- [Attack Program](#attack-program)
- [Sneaky Kernel Module](#sneaky-kernel-module)

## Overview

This assignment consists of two main components: the attack program (`sneaky_process.c`) and the sneaky kernel module (`sneaky_mod.c`). 

The attack program is a small user-level program that performs several malicious actions, including:

1. Printing its process ID
2. Modifying the `/etc/passwd` file
3. Loading the sneaky module
4. Waiting for user input
5. Unloading the sneaky module
6. Restoring the `/etc/passwd` file

The sneaky kernel module is responsible for implementing the following subversive actions:

1. Hiding the sneaky_process executable
2. Hiding the sneaky_process directory in /proc
3. Hiding modifications to the /etc/passwd file
4. Hiding the sneaky_module from the list of active kernel modules

## Attack Program

The attack program (`sneaky_process.c`) performs several malicious actions. See the detailed description above for more information on the steps it performs.

## Sneaky Kernel Module

The sneaky kernel module (`sneaky_mod.c`) implements several subversive actions. See the detailed description above for more information on the actions it performs.

