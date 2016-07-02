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

let pcap_findalldevs () =
  let pcap_findalldevs = foreign "pcap_findalldevs"
    (iface @-> ocaml_string @-> returning int) in
  let iface = allocate (ptr pcap_if) (from_voidp ( pcap_if) null) in
  let buf = String.make 65536 '\000' in
  let d = pcap_findalldevs iface (ocaml_string_start buf) in
  if d == -1
  then Result.Error (`Msg buf)
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
