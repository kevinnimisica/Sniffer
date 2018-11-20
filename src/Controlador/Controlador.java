/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Controlador;

import firewall.Capturador;
import Vista.GraphicInterface;
import Vista.SelecDev;
import java.util.List;
import java.util.ArrayList;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;

/**
 *
 * @author Kevin
 */
public class Controlador {
    private static GraphicInterface inter;
    private static Capturador cap;
    private static List<PcapPacket> paquetes;
    private static int devSel;
    private static List <PcapIf> devs;
    private static StringBuilder err;
    public Controlador ()
    {
        this.paquetes = new ArrayList<PcapPacket>();
        devs = new ArrayList<PcapIf>();
        err = new StringBuilder();
        devSel = 0;
        if (Pcap.findAllDevs(devs, err) != Pcap.OK) {
            throw new IllegalStateException(err.toString());
	}
        SelectDev();
    }
    
    public static void main(String[] args)
    {
        Controlador controller = new Controlador();
    }
    
    public void actualizar(PcapPacket packet) {
        inter.actualizar(packet);
        paquetes.add(packet);
    }
    
    public void ActDev(int i)
    {
        devSel= i;
    }
    
    public void SelectDev()
    {
        new SelecDev(devs, this).setVisible(true);
    }

    public void asigDev(int sel) {
        devSel = sel;
        inter = new GraphicInterface(this);
        inter.setVisible(true);
        cap = new Capturador(this, err, devs.get(devSel));
        
    }
    
    public void iniciarCap()
    {
        cap.start();
    }
    
    public void PararCap()
    {
        cap.parar();
    }
    
    public PcapPacket obtenerPaquete(int i)
    {
        return paquetes.get(i);
    }
}
