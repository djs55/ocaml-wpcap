open Ctypes
open Foreign

type pcap_if
let pcap_if : pcap_if structure typ = structure "pcap_if"
let next = field pcap_if "next" (ptr pcap_if)
let name = field pcap_if "name" string
let description = field pcap_if "description" string
(* struct pcap_addr * addresses *)
(* u_int flags *)
let _ = seal pcap_if

type intf = {
  name: string;
  description: string;
}

let init () =
  let _ = Dl.dlopen ~filename:"wpcap.dll" ~flags:[] in
  ()

let iface = ptr (ptr pcap_if)

let trim_error_string buf =
  try
    let i = String.index buf '\000' in
    String.sub buf 0 i
  with Not_found ->
    buf


let pcap_findalldevs () =
  let pcap_findalldevs = foreign "pcap_findalldevs"
    (iface @-> ocaml_string @-> returning int) in
  let iface = allocate (ptr pcap_if) (from_voidp ( pcap_if) null) in
  let buf = String.make 65536 '\000' in
  let d = pcap_findalldevs iface (ocaml_string_start buf) in
  if d == -1
  then Result.Error (`Msg (trim_error_string buf))
  else
    let rec loop acc ptr =
      if to_voidp ptr <> null then begin
        let iface = !@ ptr in
        let n = getf iface name in
        let d = getf iface description in
        let ptr = getf iface next in
        loop ( { name = n; description = d } :: acc ) ptr
      end else acc in
    Result.Ok (loop [] (!@ iface))

type pcap_t = unit ptr
let pcap_t : pcap_t typ = ptr void
let pcap_open_live ~device ?(snaplen=65536) ?(promisc=true) ?(to_ms=0) () =
  let pcap_open_live = foreign "pcap_open_live"
    (string @-> int @-> bool @-> int @-> ocaml_string @-> returning pcap_t) in
  let buf = String.make 65536 '\000' in
  let p = pcap_open_live device snaplen promisc to_ms (ocaml_string_start buf) in
  if to_voidp p = null
  then Result.Error (`Msg (trim_error_string buf))
  else Result.Ok p

let pcap_close p =
  let pcap_close = foreign "pcap_close"
    (pcap_t @-> returning void) in
  pcap_close p

type t = pcap_t

type timeval
let timeval: timeval structure typ = structure "timeval"
let tv_sec = field timeval "tv_sec" long
let tv_usec = field timeval "tv_usec" long
let _ = seal timeval

type pcap_pkthdr
let pcap_pkthdr : pcap_pkthdr structure typ = structure "pcap_pkthdr"
let pcap_pkthdr_ts = field pcap_pkthdr "ts" timeval
let pcap_pkthdr_caplen = field pcap_pkthdr "caplen" uint32_t
let pcap_pkthdr_len = field pcap_pkthdr "len" uint32_t
let _ = seal pcap_pkthdr

type packet = {
  caplen: int;
  len: int;
  data: Cstruct.t;
}

let pcap_next_ex t =
  let pcap_next_ex = foreign "pcap_next_ex"
    (pcap_t @-> ptr (ptr pcap_pkthdr) @-> ptr (ptr char) @-> returning int) in
  let ptr_ptr_pcap_pkthdr = allocate (ptr pcap_pkthdr) (from_voidp pcap_pkthdr null) in
  let ptr_ptr_char = allocate (ptr char) (from_voidp char null) in
  match pcap_next_ex t ptr_ptr_pcap_pkthdr ptr_ptr_char with
  | 0 -> Result.Error `Timeout
  | -1 -> Result.Error (`Msg "pcap_next_ex: some error occurred")
  | -2 -> Result.Error (`Msg "pcap_next_ex: EOF")
  | 1 ->
    let hdr = !@ !@ ptr_ptr_pcap_pkthdr in
    let caplen = Int32.to_int @@ Unsigned.UInt32.to_int32 @@ getf hdr pcap_pkthdr_caplen in
    let len = Int32.to_int @@ Unsigned.UInt32.to_int32 @@ getf hdr pcap_pkthdr_len in
    let ba = bigarray_of_ptr Ctypes_static.Array1 caplen Bigarray.char (!@ ptr_ptr_char) in
    let data = Cstruct.of_bigarray ba in
    Result.Ok { caplen; len; data }
  | x -> Result.Error (`Msg ("pcap_next_ex: unrecognised return code " ^ (string_of_int x)))
    

