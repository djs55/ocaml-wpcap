open Wpcap

let ( >>= ) m f = match m with
  | Result.Error (`Msg m) -> Result.Error (`Msg m)
  | Result.Ok x -> f x

let or_failwith = function
  | Result.Error (`Msg m) -> failwith m
  | Result.Ok x -> x

(* Use blocking I/O here so we can avoid Using Lwt_unix or Uwt. Ideally we
   would use a FLOW handle referencing a file/stream. *)
let really_write fd str =
  let rec loop ofs =
    if ofs = (String.length str)
    then ()
    else
      let n = Unix.write fd str ofs (String.length str - ofs) in
      loop (ofs + n) in
  loop 0

let start_capture filename =
  let fd = Unix.openfile filename [ Unix.O_WRONLY; Unix.O_TRUNC; Unix.O_CREAT ] 0o0644 in
  let buf = Cstruct.create Pcap.LE.sizeof_pcap_header in
  let open Pcap.LE in
  set_pcap_header_magic_number buf Pcap.magic_number;
  set_pcap_header_version_major buf Pcap.major_version;
  set_pcap_header_version_minor buf Pcap.minor_version;
  set_pcap_header_thiszone buf 0l;
  set_pcap_header_sigfigs buf 4l;
  set_pcap_header_snaplen buf 1500l;
  set_pcap_header_network buf (Pcap.Network.to_int32 Pcap.Network.Ethernet);
  really_write fd (Cstruct.to_string buf);
  fd

let capture fd pkt =
  let len = Cstruct.len pkt.data in
  let time = Unix.gettimeofday () in
  let secs = Int32.of_float time in
  let usecs = Int32.of_float (1e6 *. (time -. (floor time))) in
  let buf = Cstruct.create Pcap.sizeof_pcap_packet in
  let open Pcap.LE in
  set_pcap_packet_ts_sec buf secs;
  set_pcap_packet_ts_usec buf usecs;
  set_pcap_packet_incl_len buf @@ Int32.of_int len;
  set_pcap_packet_orig_len buf @@ Int32.of_int len;
  really_write fd (Cstruct.to_string buf);
  really_write fd (Cstruct.to_string pkt.data)

let _ =
  init ();
  match or_failwith @@ pcap_findalldevs () with
  | [] -> failwith "No devices found"
  | x :: xs ->
    Printf.printf "Choosing device %s\n%!" x.name;
    let t = or_failwith @@ pcap_open_live ~device:x.name () in
    Printf.printf "opened device for capturing\n%!";
    let fd = start_capture "capture.pcap" in
    let start = Unix.gettimeofday () in
    let rec loop () =
      let now = Unix.gettimeofday () in
      if (now -. start < 30.) then begin
        match pcap_next_ex t with
        | Result.Error `Timeout -> failwith "timeout"
        | Result.Error (`Msg m) -> failwith m
        | Result.Ok pkt ->
          Printf.printf "captured packet with caplen=%d len=%d\n%!" pkt.caplen pkt.len;
          capture fd pkt;
          loop ()
      end in
    loop ();
    pcap_close t;
    Printf.printf "closed device\n%!";
    Unix.close fd
