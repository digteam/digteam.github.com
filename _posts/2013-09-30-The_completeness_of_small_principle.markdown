---
layout:     post
title:      "完备性上的小原则"
date:       2013-09-30 12:13:58
categories: [virtualization]
tags:       [BluePill, Vmx]
author:     pjf
---

&emsp;&emsp;多年没写博客了，就先捡点剩菜剩饭炒炒，没啥营养，同学们可以随便看看。另外就是文笔真心烂，阅读的同学们需要点耐心J。
这篇博客说说一个安全防护系统完备性上所需的一个小原则：防护系统与被防护对象所用资源的完全隔离，包括防护系统自身工作所依赖的资源不能依赖被防护对象。听起来是原理很简单的一个点，实现中往往很复杂。例如操作系统隔离应用程序、虚拟机监视器隔离客户机，需要考虑方方面面、还需要处理器/芯片组硬件的大量支持。分析、设计系统时遵循许多这类小原则是必要的。
记得好像是06年的时候吧，Joanna团队在Blackhat上推出了一个基于硬件虚拟化的rootkit样本，取名Blue Pill，07年又出了改进的新版New Blue Pill。这个样本并没有任何实质的恶意行为，仅仅是一个最有名气的利用硬件虚拟化支持的原型系统。这回的话题就拿它来做例子说说，从相反的方向介绍这个原则的必要性。
New Blue Pill作为一个驱动程序加载后，沉淀下去，利用硬件虚拟化支持将原本的操作系统置入客户机中运行，其自身则以虚拟机监视器的形态存在。它的目的是展示一个利用硬件虚拟化技术的rootkit，和一些利用了硬件虚拟化支持的程序（如某些调试器）一样，它是不完备的，我们可以较为简单的检测它、脱离它的控制。阅读过new blue pill源代码的同学们很容易回忆起来，这个虚拟机监视器工作所需的不少资源都没有有效保护、客户机软件可随意访问修改，其中一个很重要的就是物理内存资源。BluePill的内存保护仅仅是虚拟内存隐藏，原理见Joanna所绘图示（图1）。其虚拟机监视器有自己的私有页表，同时将客户机操作系统所用页表中对自己的映射处理掉，因此客户机中的软件想直接访问虚拟机监视器的虚存页面自然不行。
完备性上的小原则

{:.center}
![New Blue Pill内存保护](/images/2013-09-30-new_blue_pill.jpg)  
图1. New Blue Pill内存保护
 
&emsp;&emsp;这样的虚拟内存保护有多大作用呢，因为客户机和虚拟机监视器的物理内存资源并没有有效隔离，不符合原则，所以效果只能说是聊胜于无。客户机内的软件可以轻松访问虚拟机监视器的物理内存，篡改虚拟机监视器代码数据乃至完全突破使客户机原操作系统重回Host环境（如VMX Root）运行。下面的内容阅读前需要预先熟悉一些Intel64体系结构、Windows内核上的一些知识。
先设计一个非常简单的物理内存访问库（工作于Win7 X64系统），原理为修改事先分配的NonPagedPool页所对应的PTE，使该线性地址可以用来依次映射我们指定的物理内存页面。注意x64系统如此分配一般获得一个在大页面中的线性地址，所以需要重新映射一下，以便得到可供修改的4K页对应的PTE；另外要注意的是这个映射方案是演示用的、很粗糙的，不应随意用该PTE去映射已被以NonCached等类型映射的物理空间，如外设的IO映射地址空间。

{% highlight c %}
typedef struct _MAP_STRUCT {
    PVOID OrigPage;
    PVOID MapPage;
    PMDL Mdl;
    PHYSICAL_ADDRESS MapPagePhys;
} MAP_STRUCT, *PMAP_STRUCT;

#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((ULONG_PTR)1) << VIRTUAL_ADDRESS_BITS) - 1)
 
#define PTE_BASE          0xFFFFF68000000000UI64
 
#define PTI_SHIFT 12
#define PDI_SHIFT 21
#define PPI_SHIFT 30
#define PXI_SHIFT 39
 
#define PTE_SHIFT 3
 
#define _HARDWARE_PTE_WORKING_SET_BITS  11
 
typedef struct _MMPTE {
    ULONGLONG Valid : 1;
    ULONGLONG Writable : 1;        // changed for MP version
    ULONGLONG Owner : 1;
    ULONGLONG WriteThrough : 1;
    ULONGLONG CacheDisable : 1;
    ULONGLONG Accessed : 1;
    ULONGLONG Dirty : 1;
    ULONGLONG LargePage : 1;
    ULONGLONG Global : 1;
    ULONGLONG CopyOnWrite : 1; // software field
    ULONGLONG Prototype : 1;   // software field
    ULONGLONG Write : 1;       // software field - MP change
    ULONGLONG PageFrameNumber : 28;
    ULONG64 reserved1 : 24 - (_HARDWARE_PTE_WORKING_SET_BITS+1);
    ULONGLONG SoftwareWsIndex : _HARDWARE_PTE_WORKING_SET_BITS;
    ULONG64 NoExecute : 1;
} MMPTE, *PMMPTE;
 
#define MiGetPteAddress(va) \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT) + PTE_BASE))

NTSTATUS
InitMapPage(
    OUT PMAP_STRUCT MapHandle
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PMMPTE pte;
 
    RtlZeroMemory(MapHandle, sizeof(*MapHandle));
 
    try {
 
        MapHandle->OrigPage = ExAllocatePool(NonPagedPool,
                                             PAGE_SIZE);
 
        if (MapHandle->OrigPage == NULL)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            leave;
        }
 
        MapHandle->Mdl = IoAllocateMdl(MapHandle->OrigPage,
                                       PAGE_SIZE,
                                       FALSE,
                                       FALSE,
                                       NULL);
 
        if (MapHandle->Mdl == NULL)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            leave;
        }
 
        //
        // Remap
        //
 
        MapHandle->MapPage = MmMapLockedPagesSpecifyCache(MapHandle->Mdl,
                                                          KernelMode,
                                                          MmCached,
                                                          NULL,
                                                          FALSE,
                                                          HighPagePriority);
 
        if (MapHandle->MapPage == NULL)
        {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            leave;
        }
 
        pte = MiGetPteAddress(MapHandle->MapPage);
 
        MapHandle->MapPagePhys.QuadPart = *(PULONGLONG)pte;
 
    } finally {
 
        if (!NT_SUCCESS(Status))
        {
            if (MapHandle->Mdl != NULL)
            {
                IoFreeMdl(MapHandle->Mdl);
            }
 
            if (MapHandle->OrigPage != NULL)
            {
                ExFreePool(MapHandle->OrigPage);
            }
        }
    }
 
    return Status;
}
 
PVOID
MapSpecifiedPage(
    IN PMAP_STRUCT MapHandle,
    IN PHYSICAL_ADDRESS PhysicalAddress
    )
{
    PMMPTE pte = MiGetPteAddress(MapHandle->MapPage);
 
    pte->PageFrameNumber = PhysicalAddress.QuadPart >> 12;
 
    _ReadWriteBarrier();
 
    __invlpg(MapHandle->MapPage);
 
    return MapHandle->MapPage;
}
 
VOID
FiniMapPage(
    IN PMAP_STRUCT MapHandle
    )
{
    PMMPTE pte = MiGetPteAddress(MapHandle->MapPage);
 
    pte->PageFrameNumber = MapHandle->MapPagePhys.QuadPart >> 12;
 
    MmUnmapLockedPages(MapHandle->MapPage, MapHandle->Mdl);
 
    IoFreeMdl(MapHandle->Mdl);
 
    ExFreePool(MapHandle->OrigPage);
}
{% endhighlight %}

&emsp;&emsp;然后下面的程序片段基于这个访问库，搜索当前Intel Core i3 CPU所关联的VMCS，顺便打印了其中的一些由New Blue Pill事先填充的数据：
 
{% highlight c %}
{
    ……
 
    PhysicalMemoryBlock = MmGetPhysicalMemoryRanges();
 
    if (PhysicalMemoryBlock == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
 
    Status = InitMapPage(&MapHandle);
 
    if (!NT_SUCCESS(Status))
    {
        ExFreePool(PhysicalMemoryBlock);
 
        return Status;
    }
 
    i = 0;
 
    while (PhysicalMemoryBlock[i].NumberOfBytes.QuadPart != 0)
    {
        PHYSICAL_ADDRESS BaseAddress = PhysicalMemoryBlock[i].BaseAddress;
        LARGE_INTEGER NumberOfBytes = PhysicalMemoryBlock[i].NumberOfBytes;
 
        DbgPrint("BaseAddress: %I64x\n", BaseAddress.QuadPart);
        DbgPrint("NumberOfBytes: %I64x\n", NumberOfBytes.QuadPart);
 
        while (NumberOfBytes.QuadPart > 0)
        {
            MapAddress = (PUCHAR)MapSpecifiedPage(&MapHandle, BaseAddress);
 
            if (MapAddress != NULL)
            {
                //
                // 偏移依赖处理器实现，这里是Intel Core i3.
                // 部分硬编码依赖nbp
                //
 
                if (*(PULONG)MapAddress == 0x10 &&                 // VMCS revision identifier
                    *(PULONG)(MapAddress + 0x2D0) == 0x7F &&      // Guest GDTR limit
                    *(PULONG)(MapAddress + 0x2D4) == 0xFFF &&     // Guest IDTR limit
                    *(PULONGLONG)(MapAddress + 0x358) == __readmsr(0xc0000101)) // Host GS base
                {
                    //
                    // Vmcs for current cpu.
                    //
 
                    DbgPrint("VMCS: %I64x\n", MapAddress);
                    DbgPrint("VMCS Host RIP: %I64x\n",
                             *(PULONGLONG)(MapAddress + 0x390));
                    DbgPrint("VMCS Host GDTR Base: %I64x\n",
                             *(PULONGLONG)(MapAddress + 0x368));
                    DbgPrint("VMCS Host IDTR Base: %I64x\n",
                             *(PULONGLONG)(MapAddress + 0x370));
                }
            }
 
            BaseAddress.QuadPart += PAGE_SIZE;
            NumberOfBytes.QuadPart -= PAGE_SIZE;
        }
 
        i ++;
    }
 
    FiniMapPage(&MapHandle);
 
ExFreePool(PhysicalMemoryBlock);
 
……
}
{% endhighlight %}

{:.center}
程序debug输出如图2。  
![搜索当前CPU VMCS](/images/2013-09-30-debug.jpg)  
图2. 搜索当前CPU VMCS
 
&emsp;&emsp;拿到这些信息，怎么制作“Red Pill”跳出被硬件虚拟化监控的状态就非常简单了，举个例子——比如首先可以通过Host CR3查找、修改Host页表映射加入我们的代码物理页（当然也可以直接利用Host中已经被映射的物理页面）；随后通过修改VmxVmexitHandler（图中VMCS Host RIP所指）代码或者直接替换每个VMCS的Host RIP，在合适的VM Exit时获得Host上的运行权；最后利用获得的信息修改CPU各寄存器并转移到正确位置执行。具体代码就不贴了，有兴趣的同学可以试试。完成了这些，也就突破了nbp的限制。故以nbp的需求而言，它至少要管理完整的客户页表结构（构建Shadow Page Table或使用EPT/NPT）。
反过来，我们设计虚拟化系统或是其它安防系统，就要认真思考完备性的一些原则，才有做到滴水不漏的可能。当然了这类原则也不需要无限制扩大，例如为安全卫士设计硬件虚拟化辅助的需求，其主要是以扩充X64系统安全防护能力为目标，例如使得64位windows上的卫士软件不受PatchGuard限制，获得类似32位一样的拦截、防护能力。因此不仅无需提供物理内存防护，还要从保障性能方面考虑尽量减少不必要的#VMEXIT。