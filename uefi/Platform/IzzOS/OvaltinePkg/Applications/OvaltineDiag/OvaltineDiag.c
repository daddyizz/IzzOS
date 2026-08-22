#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <Protocol/GraphicsOutput.h>

STATIC
CONST CHAR16 *
MemoryTypeName (
  IN EFI_MEMORY_TYPE Type
  )
{
  switch (Type) {
    case EfiReservedMemoryType:      return L"Reserved";
    case EfiLoaderCode:              return L"LoaderCode";
    case EfiLoaderData:              return L"LoaderData";
    case EfiBootServicesCode:        return L"BootServicesCode";
    case EfiBootServicesData:        return L"BootServicesData";
    case EfiRuntimeServicesCode:     return L"RuntimeServicesCode";
    case EfiRuntimeServicesData:     return L"RuntimeServicesData";
    case EfiConventionalMemory:      return L"Conventional";
    case EfiUnusableMemory:          return L"Unusable";
    case EfiACPIReclaimMemory:       return L"ACPIReclaim";
    case EfiACPIMemoryNVS:           return L"ACPINVS";
    case EfiMemoryMappedIO:          return L"MMIO";
    case EfiMemoryMappedIOPortSpace: return L"MMIOPort";
    case EfiPalCode:                 return L"PalCode";
    case EfiPersistentMemory:        return L"Persistent";
    default:                         return L"Unknown";
  }
}

STATIC
VOID
DumpGraphicsOutputProtocol (
  VOID
  )
{
  EFI_STATUS Status;
  EFI_GRAPHICS_OUTPUT_PROTOCOL *Gop;

  Gop = NULL;
  Status = gBS->LocateProtocol (
                  &gEfiGraphicsOutputProtocolGuid,
                  NULL,
                  (VOID **)&Gop
                  );

  if (EFI_ERROR (Status) || Gop == NULL || Gop->Mode == NULL || Gop->Mode->Info == NULL) {
    Print (L"[GOP] unavailable: %r\r\n", Status);
    return;
  }

  Print (L"[GOP] mode=%u max=%u\r\n", Gop->Mode->Mode, Gop->Mode->MaxMode);
  Print (
    L"[GOP] resolution=%ux%u pixels-per-scanline=%u format=%u\r\n",
    Gop->Mode->Info->HorizontalResolution,
    Gop->Mode->Info->VerticalResolution,
    Gop->Mode->Info->PixelsPerScanLine,
    Gop->Mode->Info->PixelFormat
    );
  Print (
    L"[GOP] framebuffer-base=0x%lx framebuffer-size=0x%lx\r\n",
    Gop->Mode->FrameBufferBase,
    Gop->Mode->FrameBufferSize
    );

  Print (L"[GOP] NOTE: values above are runtime firmware hand-off data, not hard-coded constants.\r\n");
}

STATIC
EFI_STATUS
DumpMemoryMap (
  VOID
  )
{
  EFI_STATUS Status;
  EFI_MEMORY_DESCRIPTOR *Map;
  EFI_MEMORY_DESCRIPTOR *Entry;
  UINTN MapSize;
  UINTN MapKey;
  UINTN DescriptorSize;
  UINT32 DescriptorVersion;
  UINTN Index;
  UINTN Count;

  Map = NULL;
  MapSize = 0;
  MapKey = 0;
  DescriptorSize = 0;
  DescriptorVersion = 0;

  Status = gBS->GetMemoryMap (
                  &MapSize,
                  Map,
                  &MapKey,
                  &DescriptorSize,
                  &DescriptorVersion
                  );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    Print (L"[MEM] initial GetMemoryMap failed: %r\r\n", Status);
    return Status;
  }

  MapSize += 2 * DescriptorSize;
  Map = AllocatePool (MapSize);
  if (Map == NULL) {
    Print (L"[MEM] allocation failed\r\n");
    return EFI_OUT_OF_RESOURCES;
  }

  Status = gBS->GetMemoryMap (
                  &MapSize,
                  Map,
                  &MapKey,
                  &DescriptorSize,
                  &DescriptorVersion
                  );
  if (EFI_ERROR (Status)) {
    Print (L"[MEM] GetMemoryMap failed: %r\r\n", Status);
    FreePool (Map);
    return Status;
  }

  Count = MapSize / DescriptorSize;
  Print (
    L"[MEM] descriptors=%u descriptor-size=%u version=%u\r\n",
    Count,
    DescriptorSize,
    DescriptorVersion
    );

  Entry = Map;
  for (Index = 0; Index < Count; ++Index) {
    Print (
      L"[MEM] %03u %-18s base=0x%016lx pages=0x%lx attr=0x%016lx\r\n",
      Index,
      MemoryTypeName (Entry->Type),
      Entry->PhysicalStart,
      Entry->NumberOfPages,
      Entry->Attribute
      );

    Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + DescriptorSize);
  }

  FreePool (Map);
  return EFI_SUCCESS;
}

STATIC
VOID
WaitForKey (
  VOID
  )
{
  EFI_INPUT_KEY Key;
  UINTN EventIndex;

  Print (L"\r\nPress any key to return to firmware...\r\n");
  gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &EventIndex);
  gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status;

  UNREFERENCED_PARAMETER (ImageHandle);
  UNREFERENCED_PARAMETER (SystemTable);

  Print (L"\r\nIzzOS Ovaltine Diagnostic Payload\r\n");
  Print (L"Target: OnePlus 10T 5G / ovaltine / Qualcomm SM8475 (Cape)\r\n");
  Print (L"Mode: READ-ONLY firmware inspection\r\n");
  Print (L"Storage writes: DISABLED by design\r\n\r\n");

  DumpGraphicsOutputProtocol ();
  Print (L"\r\n");

  Status = DumpMemoryMap ();
  if (EFI_ERROR (Status)) {
    Print (L"[RESULT] memory-map dump failed: %r\r\n", Status);
  } else {
    Print (L"[RESULT] memory-map dump completed\r\n");
  }

  Print (L"\r\nNo BlockIo, DiskIo, SimpleFileSystem write, UFS MMIO write, or ExitBootServices call is performed.\r\n");
  WaitForKey ();

  return EFI_SUCCESS;
}
