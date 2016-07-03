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
