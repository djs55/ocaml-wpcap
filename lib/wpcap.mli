
val init: unit -> unit
(** Open the winpcap.dll, will throw an exception if it can't be found *)


type intf = {
  name: string; (** a name suitable for pcap_open_live *)
  description: string; (** a human-readable description *)
}

val pcap_findalldevs: unit -> (intf list, [ `Msg of string ]) Result.result
(** List the network devices which can be opened with pcap_open_live *)

type t
(** A packet capture descriptor *)

val pcap_open_live: device:string -> ?snaplen:int -> ?promisc:bool -> ?to_ms:int -> unit -> (t, [ `Msg of string ]) Result.result
(** [pcap_open_live device ?snaplen ?promisc ?to_ms () opens a packet capture descriptor *)

val pcap_close: t -> unit
(** [pcap_close t] closes the descriptor and deallocates resources *)

