<!--
  Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)

  SPDX-License-Identifier: BSD-2-Clause
-->

# CAmkES Tutorial 1


This tutorial is an introduction to
CAmkES: bootstrapping a basic static CAmkES application, describing its
components, and linking them together.

## Prerequisites


1. [Set up your machine](https://docs.sel4.systems/HostDependencies#camkes-build-dependencies).
2. [Camkes hello world](https://docs.sel4.systems/Tutorials/hello-camkes-0)

## Initialising

```sh
# For instructions about obtaining the tutorial sources see https://docs.sel4.systems/Tutorials/#get-the-code
#
# Follow these instructions to initialise the tutorial
# initialising the build directory with a tutorial exercise
./init --tut hello-camkes-1
# building the tutorial exercise
cd hello-camkes-1_build
ninja
```


## Outcomes

1. Understand the structure of a CAmkES application, as a described,
well-defined, static system.
1. Understand the file-layout of a CAmkES ADL project.
1. Become acquainted with the basics of creating a practical CAmkES application.

## Background

The fundamentals of CAmkES are the component, the interface and the connection.

### Components

*Components* are logical
groupings of code and resources. They communicate with other component
instances via well-defined interfaces which must be statically defined,
over communication channels. This tutorial will lead you through the
construction of a CAmkES application with two components: an Echo
server, and its Client that makes calls to it. These components are
defined when you initialise your build repository, found in
the following camkes file:

- `hello-camkes-1/hello-1.camkes`

Find the Component manual section here:
<https://github.com/seL4/camkes-tool/blob/master/docs/index.md#component>

### Connections

 The second fundamental component of CAmkES applications
is the *Connection*: a connection is the representation of a method of
communication between two software components in CAmkES. The underlying
implementation may be shared memory, synchronous IPC, notifications or
some other implementation-provided means. In this particular tutorial,
we are using synchronous IPC. In implementation terms, this boils down
to the `seL4_Call` syscall on seL4.

Find the "Connection" keyword manual section here:
<https://github.com/seL4/camkes-tool/blob/master/docs/index.md#connection>

### Interfaces

 All communications over a CAmkES connection must be well
defined: static systems' communications should be able to be reasoned
about at build time. All the function calls which will be delivered over
a communication channel then, also are well defined, and logically
grouped so as to provide clear directional understanding of all
transmissions over a connection. Components are connected together in
CAmkES, yes -- but the interfaces that are exposed over each connection
for calling by other components, are also described. 

There are different
kinds of interfaces: 
-Dataports,
-Procedural interfaces,
-and Notifications.

This tutorial will lead you through the construction of a Procedural
interface, which is an interface over which function calls are made
according to a well-defined pre-determined API. The keyword for this
kind of interface in CAmkES is `procedure`. The definition of this
Procedure interface may be found here:
`hello-camkes-1/interfaces/HelloSimple.idl4`

Find the "Procedure" keyword definition here:
<https://github.com/seL4/camkes-tool/blob/master/docs/index.md#procedure>

### Component source 

 Based on the ADL, CAmkES generates boilerplate which
conforms to your system's architecture, and enables you to fill in the
spaces with your program's logic. The two generated files in this
tutorial application are, in accordance with the Components we have
defined:

- `hello-camkes-1/components/Echo/src/echo.c`
- `hello-camkes-1/components/Client/src/client.c`

Now when it comes to invoking the functions that were defined in the
Interface specification
(`hello-camkes-1/interfaces/HelloSimple.idl4`),
you must prefix the API function name with the name of the Interface
instance that you are exposing over the particular connection.

The reason for this is because it is possible for one component to
expose an interface multiple times, with each instance of that interface
referring to a different function altogether. For example, if a
composite device, such as a network card with with a serial interface
integrated into it, exposes two instances of a procedural interface that
has a particular procedure named `send()` -- how will the caller of
`send()` know whether his `send()` is the one that is exposed over the
NIC connection, or the serial connection?

The same component provides both. Therefore, CAmkES prefixes the
instances of functions in an Interface with the Interface-instance's
name. In the dual-function NIC device's case, it might have a
`provides <INTERFACE_NAME> serial` and a `provides <INTERFACE_NAME> nic`.
When a caller wants to call for the NIC-send, it would call,
nic_send(), and when a caller wants to invoke the Serial-send, it would
call, "serial_send()".

So if the `Hello` interface is provided once by `Echo` as `a`, you would
call for the `a` instance of Echo's `Hello` by calling for `a_hello()`.
But what if Echo had provided 2 instances of the `Hello` interface, and
the second one was named `a2`? Then in order to call on that second
`Hello` interface instance on Echo, you would call `a2_hello()`.

## Exercises


**Exercise** First modify `hello-1.camkes`. Define instances of `Echo` and `Client` in the 
`composition` section of the ADL.

```
assembly {
    composition {
         component EmptyComponent empty;
         // TODO remove the empty component, and define an Echo and a Client component
assembly {
    composition {
         component EmptyComponent empty;
         component Client client;
         component Echo echo;
```

**Exercise** Now add a connection from `client.hello` to `echo.hello`.

```
        /* hint 1: use seL4RPCCall as the connector (or you could use seL4RPC if you prefer)
         * hint 2: look at
         * https://github.com/seL4/camkes-tool/blob/master/docs/index.md#creating-an-application
         */
        connection seL4RPCCall hello_con(from client.hello, to echo.hello);
```

**Exercise** Define the interface for hello in `interfaces/HelloSimple.idl4`. 

```c
/* Simple RPC interface */
procedure HelloSimple {
    /* TODO define RPC functions */
    /* hint 1: define at least one function that takes a string as input parameter. call it say_hello. no return value
     * hint 2: look at https://github.com/seL4/camkes-tool/blob/master/docs/index.md#creating-an-application
     */
};
```

**Exercise** Implement the RPC hello function.

```c
/*
 * CAmkES tutorial part 1: components with RPC. Server part.
 */
#include <stdio.h>

/* generated header for our component */
#include <camkes.h>
/* TASK 5: implement the RPC function. */
/* hint 1: the name of the function to implement is a composition of an interface name and a function name:
 * i.e.: <interface>_<function>
 * hint 2: the interfaces available are defined by the component, e.g. in hello-1.camkes
 * hint 3: the function name is defined by the interface definition, e.g. in interfaces/HelloSimple.idl4
 * hint 4: so the function would be: hello_say_hello()
 * hint 5: the CAmkES 'string' type maps to 'const char *' in C
 * hint 6: make the function print out a mesage using printf
 * hint 7: look at https://github.com/seL4/camkes-tool/blob/master/docs/index.md#creating-an-application
 */
void hello_say_hello(const char *str) {
    printf("Component %s saying: %s\n", get_instance_name(), str);
}
```

**Exercise** Invoke the RPC function in `components/Client/src/client.c`.
```c
/*
 * CAmkES tutorial part 1: components with RPC. Client part.
 */

#include <stdio.h>

/* generated header for our component */
#include <camkes.h>

/* run the control thread */
int run(void) {
    printf("Starting the client\n");
    printf("-------------------\n");
    /* TODO: invoke the RPC function */
    /* hint 1: the name of the function to invoke is a composition of an interface name and a function name:
     * i.e.: <interface>_<function>
     * hint 2: the interfaces available are defined by the component, e.g. in hello-1.camkes
     * hint 3: the function name is defined by the interface definition, e.g. in interfaces/HelloSimple.idl4
     * hint 4: so the function would be:  hello_say_hello()
     * hint 5: look at https://github.com/seL4/camkes-tool/blob/master/docs/index.md#creating-an-application
     */
    char *shello = "hello world";
    hello_say_hello(shello);

    printf("After the client\n");
    return 0;
}
```

### TASK 5
 Here you define the callee-side invocation functions for
the Hello interface exposed by Echo.

## Done

Now build and run the project, if it compiles: Congratulations! Be sure to read up on the keywords and
structure of ADL: it's key to understanding CAmkES. And well done on
writing your first CAmkES application.


---
## Getting help
Stuck? See the resources below.
* [FAQ](https://docs.sel4.systems/FrequentlyAskedQuestions)
* [seL4 Manual](http://sel4.systems/Info/Docs/seL4-manual-latest.pdf)
* [Debugging guide](https://docs.sel4.systems/DebuggingGuide.html)
* [seL4 Discourse forum](https://sel4.discourse.group)
* [Developer's mailing list](https://lists.sel4.systems/postorius/lists/devel.sel4.systems/)
* [Mattermost Channel](https://mattermost.trustworthy.systems/sel4-external/)
