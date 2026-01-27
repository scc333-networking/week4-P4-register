/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*
 * Define the headers the program will recognize
 */
 #define CPU_PORT 255


// register<bit<32>>(256) packet_counter;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

@controller_header("packet_in")
header packet_in_t {
    bit<7> pad;
    bit<9> ingress_port;
}

/*
 * This is a special header for the packet out message.
 * You can set it in your controller using the metadata 
 * element.
 */
@controller_header("packet_out")
header packet_out_t {
    bit<7> pad;
    bit<9> ingress_port;
}

struct metadata {
    bit<7> pad;
    bit<9> ingress_port;
}

struct headers {
    packet_in_t packetin;
    packet_out_t packetout;
    ethernet_t   ethernet;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select (standard_metadata.ingress_port) {
            CPU_PORT: parse_controller_packet_out_header;
            default: parse_ethernet;
        }
    }
    state parse_controller_packet_out_header {
        packet.extract(hdr.packetout);
        packet.extract(hdr.ethernet);
        log_msg("pad {}, ingress {}",{hdr.packetout.pad, hdr.packetout.ingress_port});
        transition accept;
    }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // Register to count packets from each host (indexed by source MAC)
    register<bit<32>>(256) packet_counter;
    register<bit<48>>(256) timestamp;
    register<bit<1>>(256) drop; // to avoid empty register issue

    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    action forward_to_cpu() {
        meta.ingress_port = standard_metadata.ingress_port;
        standard_metadata.egress_spec = CPU_PORT;
    }

    action broadcast() {
        standard_metadata.mcast_grp = 1; // Broadcast
    }

    action rate_limit(bit<32> rate) {
        bit<32> index;
        bit<32> count;

        index = (bit<32>)(hdr.ethernet.srcAddr[7:0]); // Simple hash to index using the lower 8 bits of MAC
        packet_counter.read(count, index);
        packet_counter.write(index, count + 1);

        // use logical operator to set drop flag
        drop.write(index, (bit<1>)(count > rate));

    }

    table smac {
        key = {
            hdr.ethernet.srcAddr: exact;
        }

        actions = {
            NoAction;
            forward_to_cpu;
        }

        size = 256;
        default_action = forward_to_cpu();
    }

    table dmac {
        key = {
            hdr.ethernet.dstAddr: exact;
        }

        actions = {
            forward;
            broadcast;
        }
        size = 256;
        default_action = broadcast();
    }

    table threshold_table {
        key = {
            hdr.ethernet.srcAddr: exact;
        }

        actions = {
            NoAction;
            rate_limit;
        }
        size = 256;
        default_action = NoAction();
    }

    apply {
        if (hdr.ethernet.isValid()) {
             if (smac.apply().hit) {
                // source MAC known
                if (dmac.apply().hit) {
                    if (threshold_table.apply().hit) {
                        // rate limiting applied
                        bit<32> index;
                        bit<1> drop_flag;
                        bit<48> last_time;
                        bit<32> time_diff;
                        index = (bit<32>)(hdr.ethernet.srcAddr[7:0]); // Simple hash to index using the lower 8 bits of MAC
                        timestamp.read(last_time, index);
                        // the ingress_global_timestamp is in microseconds (10^-6 seconds)
                        time_diff = (bit<32>)(standard_metadata.ingress_global_timestamp - last_time)
                        drop.read(drop_flag, index);
                        // Unfortunately, P4 on stratum does not support direct if conditions inside actions, so we use a register to store the drop flag
                        if (drop_flag == 1) {
                            mark_to_drop(standard_metadata);
                        }

                        // Update timestamp and reset counter if more than 1 second has passed or if no previous timestamp exists (== 0)
                        if (last_time == 0) {
                            // first packet from this host
                            log_msg("First packet from {}, setting timestamp", {hdr.ethernet.srcAddr});
                            timestamp.write(index, standard_metadata.ingress_global_timestamp);
                        }

                        // If more than 1 second has passed, reset counter and timestamp
                        if (time_diff >= 1000000) {
                            log_msg("More than a second {} elapsed for {}", {time_diff, index});
                            timestamp.write(index, standard_metadata.ingress_global_timestamp);
                            packet_counter.write(index, 0);
                            drop.write(index, 0);
                        }
                    }
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {
        // log_msg("egress port {}, packet out port {}",{standard_metadata.ingress_port, hdr.packetout.ingress_port});
        if (standard_metadata.egress_port == CPU_PORT) {
            // send packet to controller
            hdr.packetin.setValid();
            hdr.packetin.ingress_port = meta.ingress_port;
        }
        if (standard_metadata.egress_port == standard_metadata.ingress_port) {
            drop();
        }
        if (standard_metadata.ingress_port == CPU_PORT && standard_metadata.egress_port == hdr.packetout.ingress_port) {
            // log_msg("Suppresss message on port {}",{standard_metadata.egress_port});
            drop();
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
		// parsed headers have to be added again into the packet
 
        packet.emit(hdr.packetin);
        packet.emit(hdr.packetout);
		packet.emit(hdr.ethernet);
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
	MyParser(),
	MyVerifyChecksum(),
	MyIngress(),
	MyEgress(),
	MyComputeChecksum(),
	MyDeparser()
) main;