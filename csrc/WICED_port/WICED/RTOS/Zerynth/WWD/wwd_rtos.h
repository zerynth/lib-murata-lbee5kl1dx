#ifndef INCLUDED_WWD_RTOS_H_
#define INCLUDED_WWD_RTOS_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "vosal.h"

extern void vPortSVCHandler    ( void );
extern void xPortPendSVHandler ( void );
extern void xPortSysTickHandler( void );

/* Define interrupt handlers needed by FreeRTOS. These defines are used by the
 * vector table.
 */
#define SVC_irq     vPortSVCHandler
#define PENDSV_irq  xPortPendSVHandler
#define SYSTICK_irq xPortSysTickHandler

#define RTOS_HIGHER_PRIORTIY_THAN(x)     ((x)+1)
#define RTOS_LOWER_PRIORTIY_THAN(x)      ((x)-1)
#define RTOS_LOWEST_PRIORITY             (VOS_PRIO_IDLE)
#define RTOS_HIGHEST_PRIORITY            (VOS_PRIO_HIGHEST)
#define RTOS_DEFAULT_THREAD_PRIORITY     (VOS_PRIO_NORMAL)

#define RTOS_USE_DYNAMIC_THREAD_STACK
#define WWD_THREAD_STACK_SIZE            (544 + 4096 + 1400)

/*
 * The number of system ticks per second
 */
#define SYSTICK_FREQUENCY  (1000)

/******************************************************
 *             Structures
 ******************************************************/

typedef VSemaphore   host_semaphore_type_t;  /** NoOS definition of a semaphore */
typedef VSemaphore   host_mutex_type_t;  /** NoOS definition of a semaphore */
typedef VThread   	host_thread_type_t;     /** NoOS definition of a thread handle - Would be declared void but that is not allowed. */
typedef VMailBox   	host_queue_type_t;      /** NoOS definition of a message queue */


typedef struct
{
    uint8_t info;    /* not supported yet */
} host_rtos_thread_config_type_t;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ifndef INCLUDED_WWD_RTOS_H_ */