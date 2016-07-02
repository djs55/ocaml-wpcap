open Wpcap

let _ =
  init ();
  match pcap_findalldevs () with
  | Result.Error (`Msg m) -> failwith m
  | Result.Ok all ->
    List.iteri (fun i intf ->
      Printf.printf "%d: %s\n" i intf.name;
      Printf.printf "%d: %s\n" i intf.description;
    ) all
