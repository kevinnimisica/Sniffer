/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package firewall;

import Controlador.Controlador;
import static java.lang.Thread.MAX_PRIORITY;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.winpcap.*;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;

/**
 *
 * @author Kevin
 */
public class Capturador implements Runnable{

    private static Controlador contro;
    private static String nombre;
    private static PcapIf device;
    private static StringBuilder errores;
    private static PcapPacketHandler<String> jpacketHandler;
    private static boolean on;
    private static Pcap pcap;
    private static Thread hilo;
    private static int cantHilo = 0;
    
    public Capturador(Controlador control, StringBuilder err, PcapIf deviceS)
    {
        contro = control;
        errores = err;
        device = deviceS;
        
        jpacketHandler = new PcapPacketHandler<String>() {
            public void nextPacket(PcapPacket packet, String user) {
                byte[] sIP = new byte[4];
                byte[] dIP = new byte[4];
                Ip4 ip = new Ip4();
                if(on == false)
                    pcap.breakloop();
                if (packet.hasHeader(ip) == false) 
                {
                    return; // Not IP packet
                }
                // Use jNetPcap format  utilities 
                dIP = packet.getHeader(ip).destination();
                sIP = packet.getHeader(ip).source();  
                Icmp icmp = new Icmp();
                Ethernet eth = new Ethernet();
                if (packet.hasHeader(icmp) ) {
                    
                }
                if (packet.hasHeader(eth) ) {
                    
                    String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                    String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
                    if(packet.hasHeader(Ip4.ID))
                    {
                        contro.actualizar(packet);
                    }
                }  
            }
        };
    }
    
    @Override
    public void run() {
        on = true;
        pcap = Pcap.openLive(device.getName(), Pcap.DEFAULT_SNAPLEN, Pcap.DEFAULT_PROMISC, 1, errores);
        if(pcap == null)
        {
            throw new IllegalArgumentException(errores.toString());
        }
        pcap.loop(-1, jpacketHandler,"");
        pcap.close();
        hilo.interrupt();
    }
    
    public void start()
    {
        on = true;
        if(hilo == null)
        {
            hilo = new Thread(this, "Hilo ");
            hilo.setPriority(MAX_PRIORITY);
            hilo.start();
        }
        else
        {
            hilo = new Thread(this, "Hilo "+ (++cantHilo));
            hilo.setPriority(MAX_PRIORITY);
            hilo.start();
        }
    }
    
    public void parar(){
        on = false;
    }
    
    public void serDevice(PcapIf dev)
    {
        this.device = dev;
    }
}
