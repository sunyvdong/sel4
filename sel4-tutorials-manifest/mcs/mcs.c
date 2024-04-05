

#include <assert.h>
#include <sel4/sel4.h>
#include <stdio.h>
#include <string.h>
#include <utils/util.h>

// CSlots pre-initialised in this CSpace
// capability to a scheduling context
extern seL4_CPtr sched_context;



// the seL4_SchedControl capabilty for the current core
extern seL4_CPtr sched_control;
// capability to the tcb of the server process
extern seL4_CPtr server_tcb;
// capability to the tcb of the spinner process
extern seL4_CPtr spinner_tcb;
// capability to the tcb of the sender process
extern seL4_CPtr sender_tcb;
// capability to an endpoint, shared with 'sender' and 'server' 
extern seL4_CPtr endpoint;
// capability to a reply object
extern seL4_CPtr reply;

int main(int c, char *argv[]) {
    seL4_Error error;

    // configure sc
    
    error = seL4_SchedControl_Configure(sched_control, sched_context, US_IN_S, US_IN_S, 0, 0);
    ZF_LOGF_IF(error != seL4_NoError, "Failed to configure schedcontext");
    // bind it to `spinner_tcb`
    
    error = seL4_SchedContext_Bind(sched_context, spinner_tcb);
    ZF_LOGF_IF(error != seL4_NoError, "Failed to bind sched_context to round_robin_tcb");

    int i = 0; 
    for (; i < 9; i++) {
        seL4_Yield();
        printf("Tick %d\n", i);
    }

    
    //TODO reconfigure sched_context to be periodic
    
    //TODO unbind sched_context to stop yielding thread 

    
    //TODO bind sched_context to sender_tcb
    
    //TODO reconfigure sched_context to be periodic with 6 extra refills
    for (int i = 0; i < 9; i++) {
        seL4_Wait(endpoint, NULL);
        printf("Tock %d\n", (int) seL4_GetMR(0));
    }
 
    
    error = seL4_SchedContext_UnbindObject(sched_context, sender_tcb);
    ZF_LOGF_IF(error, "Failed to unbind sched_context from sender_tcb");
    
    /* suspend the sender to get them off endpoint */
    error = seL4_TCB_Suspend(sender_tcb);
    ZF_LOGF_IF(error, "Failed to suspend sender_tcb");

    error = seL4_TCB_SetPriority(server_tcb, server_tcb, 253);
    ZF_LOGF_IF(error, "Failed to decrease server's priority");
    printf("Starting server\n");
    
    //TODO bind sched_context to server_tcb
    // wait for it to initialise
    printf("Wait for server\n"); 
    seL4_Wait(endpoint, NULL);
   
    
    // convert to passive
    error = seL4_SchedContext_Unbind(sched_context);
    ZF_LOGF_IF(error != seL4_NoError, "Failed to unbind sched context");

    const char *messages[] = {
        "running", 
        "passive",
        "echo server",
        NULL,
    };
 
    for (int i = 0; messages[i] != NULL; i++) {
        int m = 0;
        for (; m < strlen(messages[i]) && m < seL4_MsgMaxLength; m++) {
            seL4_SetMR(m, messages[i][m]);
        }
        seL4_Call(endpoint, seL4_MessageInfo_new(0, 0, 0, m));
    }

    
    //TODO reconfigure sched_context with 10s period, 1ms budget, 0 extra refills and data of 5.
    
    //TODO set endpoint as the timeout fault handler for spinner_tcb
    
    error = seL4_SchedContext_Bind(sched_context, spinner_tcb);
    ZF_LOGF_IF(error, "Failed to bind sched_context to spinner_tcb");

    seL4_MessageInfo_t info = seL4_Recv(endpoint, NULL, reply);
    /* parse the fault info from the message */
    seL4_Fault_t fault = seL4_getArchFault(info);
    ZF_LOGF_IF(seL4_Fault_get_seL4_FaultType(fault) != seL4_Fault_Timeout, "Not a timeout fault");
    printf("Received timeout fault\n");
    ZF_LOGF_IF(seL4_Fault_Timeout_get_data(fault) != 5, "Incorrect data");
    
    printf("Success!\n");

    return 0;
}