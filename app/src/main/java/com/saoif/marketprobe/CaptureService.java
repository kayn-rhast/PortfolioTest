package com.saoif.marketprobe;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.IBinder;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.io.FileOutputStream;
import java.io.File;

public class CaptureService extends Service {
  volatile boolean active=false;
  DatagramSocket socket;
  Thread thread;
  long packets,bytes,filebytes;
  String error="";
  @Override public void onCreate(){
      super.onCreate();
      if(Build.VERSION.SDK_INT>=26){
         NotificationChannel ch=new NotificationChannel("market_probe","SAOIF Capture",NotificationManager.IMPORTANCE_LOW);
         ((NotificationManager)getSystemService(NOTIFICATION_SERVICE)).createNotificationChannel(ch);
      }
  }
  Notification notification(){
      Intent launch=new Intent(this,MainActivity.class);
      PendingIntent p=PendingIntent.getActivity(this,0,launch,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_IMMUTABLE);
      Notification.Builder builder=Build.VERSION.SDK_INT>=26?new Notification.Builder(this,"market_probe"):new Notification.Builder(this);
      return builder.setSmallIcon(android.R.drawable.stat_sys_download).setContentTitle("SAOIF Market Probe")
      .setContentText("Capturing SAOIF traffic locally").setContentIntent(p).setOngoing(true).build();
  }
  @Override public int onStartCommand(Intent i,int flags,int startId){
      if(i!=null&&"STOP".equals(i.getAction())){stopSelf();return START_NOT_STICKY;}
      startForeground(1821,notification());
      if(active)return START_NOT_STICKY;
      active=true;packets=bytes=filebytes=0;error="";
      thread=new Thread(this::capture,"SAOIF-PCAP-Collector");thread.start();
      return START_NOT_STICKY;
  }
  void writeStats(){
      SharedPreferences.Editor e=getSharedPreferences("market_probe",MODE_PRIVATE).edit();
      e.putBoolean("active",active).putLong("packets",packets).putLong("bytes",bytes).putLong("filebytes",filebytes).putString("error",error).apply();
  }
  void capture(){
      try(FileOutputStream output=new FileOutputStream(new File(getFilesDir(),"saoif.pcap"),false)){
         socket=new DatagramSocket(null);
         socket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),5123));
         socket.setSoTimeout(1000);
         byte[] data=new byte[65535];DatagramPacket pkt=new DatagramPacket(data,data.length);
         boolean header=false;
         writeStats();
         while(active){
            pkt.setLength(data.length);
            try{socket.receive(pkt);}catch(SocketTimeoutException e){writeStats();continue;}
            int n=pkt.getLength();if(n<1)continue;
            if(!header){
               if(n==24 && (data[0]==(byte)0xd4||data[0]==(byte)0xa1)){output.write(data,0,n);filebytes+=n;header=true;continue;}
               byte[] global={(byte)0xd4,(byte)0xc3,(byte)0xb2,(byte)0xa1,2,0,4,0,0,0,0,0,0,0,0,0,(byte)0xff,(byte)0xff,0,0,101,0,0,0};
               output.write(global);filebytes+=global.length;header=true;
            }
            packets++;bytes+=Math.max(0,n-16);
            if(filebytes+n<24L*1024*1024){output.write(data,0,n);filebytes+=n;}
            if((packets%16)==0) {output.flush();writeStats();}
         }
         output.flush();
      }catch(Exception e){if(active)error=e.getClass().getSimpleName()+": "+e.getMessage();}
      finally{active=false;if(socket!=null){socket.close();socket=null;}writeStats();}
  }
  @Override public void onDestroy(){active=false;if(socket!=null)socket.close();if(thread!=null)try{thread.join(1500);}catch(InterruptedException e){Thread.currentThread().interrupt();}writeStats();super.onDestroy();}
  @Override public IBinder onBind(Intent intent){return null;}
}
