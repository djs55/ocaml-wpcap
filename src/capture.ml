open Wpcap

let ( >>= ) m f = match m with
  | Result.Error (`Msg m) -> Result.Error (`Msg m)
  | Result.Ok x -> f x

let _ =
  init ();
  match (
    pcap_findalldevs ()
    >>= function
    | [] -> Result.Error (`Msg "No devices found")
    | x :: xs ->
      Printf.printf "Choosing device %s\n%!" x.name;
      pcap_open_live ~device:x.name ()
      >>= fun t ->
      Printf.printf "opened device for capturing\n%!";
      pcap_close t;
      Printf.printf "closed device\n%!";
      Result.Ok ()
  ) with
  | Result.Ok () -> ()
  | Result.Error (`Msg m) -> failwith m
