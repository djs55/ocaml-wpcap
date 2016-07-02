
val init: unit -> unit
(** Open the winpcap.dll, will throw an exception if it can't be found *)


type intf = {
  name: string; (** a name suitable for pcap_open_live *)
  description: string; (** a human-readable description *)
}

val pcap_findalldevs: unit -> (intf list, [ `Msg of string ]) Result.result
(** List the network devices which can be opened with pcap_open_live *)
