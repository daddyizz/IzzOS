#include <Uefi.h>

#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#include <Protocol/GraphicsOutput.h>

#define MEMORY_MAP_MAX_ATTEMPTS 4
#define KEY_READ_MAX_ATTEMPTS   3

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
    L"[GOP] framebuffer-base=0x%Lx framebuffer-size=0x%Lx\r\n",
    (UINT64)Gop->Mode->FrameBufferBase,
    (UINT64)Gop->Mode->FrameBufferSize
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
  UINTN Attempt;
  UINTN AllocationSize;
  UINTN SlackSize;

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

  if (DescriptorSize < sizeof (EFI_MEMORY_DESCRIPTOR)) {
    Print (
      L"[MEM] invalid descriptor size: %Lu (minimum %Lu)\r\n",
      (UINT64)DescriptorSize,
      (UINT64)sizeof (EFI_MEMORY_DESCRIPTOR)
      );
    return EFI_COMPROMISED_DATA;
  }

  for (Attempt = 0; Attempt < MEMORY_MAP_MAX_ATTEMPTS; ++Attempt) {
    if (DescriptorSize > (MAX_UINTN / 2)) {
      Print (L"[MEM] descriptor slack multiplication would overflow\r\n");
      Status = EFI_BAD_BUFFER_SIZE;
      break;
    }

    SlackSize = 2 * DescriptorSize;
    if (MapSize > MAX_UINTN - SlackSize) {
      Print (L"[MEM] map size overflow while adding descriptor slack\r\n");
      Status = EFI_BAD_BUFFER_SIZE;
      break;
    }

    AllocationSize = MapSize + SlackSize;
    Map = AllocatePool (AllocationSize);
    if (Map == NULL) {
      Print (L"[MEM] allocation failed: requested=%Lu\r\n", (UINT64)AllocationSize);
      Status = EFI_OUT_OF_RESOURCES;
      break;
    }

    MapSize = AllocationSize;
    Status = gBS->GetMemoryMap (
                    &MapSize,
                    Map,
                    &MapKey,
                    &DescriptorSize,
                    &DescriptorVersion
                    );
    if (!EFI_ERROR (Status)) {
      break;
    }

    FreePool (Map);
    Map = NULL;

    if (Status != EFI_BUFFER_TOO_SMALL) {
      Print (L"[MEM] GetMemoryMap failed on attempt %Lu: %r\r\n", (UINT64)(Attempt + 1), Status);
      break;
    }

    if (DescriptorSize < sizeof (EFI_MEMORY_DESCRIPTOR)) {
      Print (L"[MEM] descriptor size became invalid during retry: %Lu\r\n", (UINT64)DescriptorSize);
      Status = EFI_COMPROMISED_DATA;
      break;
    }

    Print (
      L"[MEM] map grew during capture; retrying (%Lu/%u), required=%Lu\r\n",
      (UINT64)(Attempt + 1),
      MEMORY_MAP_MAX_ATTEMPTS,
      (UINT64)MapSize
      );
  }

  if (EFI_ERROR (Status)) {
    if (Map != NULL) {
      FreePool (Map);
    }

    if (Status == EFI_BUFFER_TOO_SMALL) {
      Print (L"[MEM] memory map kept growing after %u attempts\r\n", MEMORY_MAP_MAX_ATTEMPTS);
    }

    return Status;
  }

  if (Map == NULL || DescriptorSize == 0 || MapSize == 0 || (MapSize % DescriptorSize) != 0) {
    Print (
      L"[MEM] invalid final map geometry: map=%p size=%Lu descriptor-size=%Lu\r\n",
      Map,
      (UINT64)MapSize,
      (UINT64)DescriptorSize
      );
    if (Map != NULL) {
      FreePool (Map);
    }
    return EFI_COMPROMISED_DATA;
  }

  Count = MapSize / DescriptorSize;
  Print (
    L"[MEM] descriptors=%Lu descriptor-size=%Lu version=%u\r\n",
    (UINT64)Count,
    (UINT64)DescriptorSize,
    DescriptorVersion
    );

  Entry = Map;
  for (Index = 0; Index < Count; ++Index) {
    Print (
      L"[MEM] %03Lu %-18s base=0x%016Lx pages=0x%Lx attr=0x%016Lx\r\n",
      (UINT64)Index,
      MemoryTypeName (Entry->Type),
      (UINT64)Entry->PhysicalStart,
      (UINT64)Entry->NumberOfPages,
      (UINT64)Entry->Attribute
      );

    Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + DescriptorSize);
  }

  FreePool (Map);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
WaitForKey (
  VOID
  )
{
  EFI_STATUS Status;
  EFI_INPUT_KEY Key;
  UINTN EventIndex;
  UINTN Attempt;

  if (gBS == NULL || gST == NULL || gST->ConIn == NULL ||
      gST->ConIn->WaitForKey == NULL || gST->ConIn->ReadKeyStroke == NULL) {
    Print (L"\r\n[INPUT] console input protocol unavailable; returning without key wait.\r\n");
    return EFI_UNSUPPORTED;
  }

  Print (L"\r\nPress any key to return to firmware...\r\n");

  for (Attempt = 0; Attempt < KEY_READ_MAX_ATTEMPTS; ++Attempt) {
    EventIndex = 0;
    Status = gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &EventIndex);
    if (EFI_ERROR (Status)) {
      Print (L"[INPUT] WaitForEvent failed: %r\r\n", Status);
      return Status;
    }

    Status = gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
    if (!EFI_ERROR (Status)) {
      return EFI_SUCCESS;
    }

    if (Status != EFI_NOT_READY) {
      Print (L"[INPUT] ReadKeyStroke failed: %r\r\n", Status);
      return Status;
    }
  }

  Print (L"[INPUT] key remained unavailable after %u attempts; returning safely.\r\n", KEY_READ_MAX_ATTEMPTS);
  return EFI_NOT_READY;
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status;
  EFI_STATUS InputStatus;

  (VOID)ImageHandle;
  (VOID)SystemTable;

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
  InputStatus = WaitForKey ();
  if (EFI_ERROR (InputStatus) && InputStatus != EFI_UNSUPPORTED && InputStatus != EFI_NOT_READY) {
    Print (L"[RESULT] console input wait ended with: %r\r\n", InputStatus);
  }

  return EFI_SUCCESS;
}
