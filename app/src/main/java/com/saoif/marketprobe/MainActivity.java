package com.saoif.marketprobe;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import org.json.JSONObject;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class MainActivity extends Activity {
    static final String GAME="com.bandainamcoent.saoifww";
    static final String PCAP="com.emanuelef.remote_capture";
    static final int REQ_START=10,REQ_STOP=11,REQ_PCAP=12,REQ_JSON=13;
    static final int BG=Color.rgb(10,16,28), PANEL=Color.rgb(22,33,52),CYAN=Color.rgb(64,207,241),FG=Color.WHITE;
    final Handler handler=new Handler(Looper.getMainLooper());
    TextView stateText,statsText;
    final Runnable refresh=new Runnable(){
      public void run(){
        SharedPreferences p=getSharedPreferences("market_probe",MODE_PRIVATE);
        if(stateText!=null){
           boolean active=p.getBoolean("active",false);
           stateText.setText(active?"● Capture active":"○ Capture inactive");
           stateText.setTextColor(active?0xff68e8b6:0xffffffff);
           statsText.setText("Packets received: "+p.getLong("packets",0)+"\nBytes captured: "+
               p.getLong("bytes",0)+"\nPCAP saved: "+p.getLong("filebytes",0)+
               " bytes\nErrors: "+p.getString("error","none")+
               "\nMarket prices decoded: NO (feasibility test only)");
        }
        handler.postDelayed(this,1500);
      }
    };
    @Override public void onCreate(Bundle state){
       super.onCreate(state);getWindow().setStatusBarColor(BG);getWindow().setNavigationBarColor(BG);
       ScrollView sc=new ScrollView(this);sc.setBackgroundColor(BG);
       LinearLayout root=new LinearLayout(this);root.setOrientation(1);root.setPadding(dp(20),dp(24),dp(20),dp(32));sc.addView(root);
       label(root,"SAO INTEGRAL FACTOR · v0.1.1",13,CYAN,true);
       label(root,"Market Probe",30,FG,true);
       label(root,"No root · No OCR · No screenshot · No game modification",13,0xffa8bdd4,false);
       space(root,18);
       LinearLayout box=panel(root);
       label(box,"NETWORK CAPTURE",12,CYAN,true);
       stateText=label(box,"Ready to capture",20,FG,true);
       label(box,"Start capture, open the game, and enter the Market once. The app saves SAOIF network packets locally so we can test whether bulk market data is even transmitted.",14,0xffc4d1e0,false);
       addButton(box,"Start capture → Open game",CYAN,()->startCapture());
       addButton(box,"Stop capture",0xff37465c,()->stopCapture());
       addButton(box,"Install PCAPdroid",0xff273b53,()->installPcap());
       LinearLayout diag=panel(root);
       label(diag,"DIAGNOSTICS",12,CYAN,true);
       statsText=label(diag,"No capture yet",15,FG,false);
       addButton(diag,"Save diagnostic report (.json)",0xff273b53,()->saveReport());
       addButton(diag,"Export private packet capture (.pcap)",0xff273b53,()->savePcap());
       LinearLayout note=panel(root);
       label(note,"IMPORTANT",12,CYAN,true);
       label(note,"This first APK is a network feasibility probe — NOT an automatic live-price reader. Protected game traffic may be encrypted and entering the Market may not fetch every listing. PCAP can contain session-sensitive data; do not share publicly.",14,0xffc4d1e0,false);
       setContentView(sc);
    }
    int dp(int v){return (int)(v*getResources().getDisplayMetrics().density+0.5f);}
    TextView label(LinearLayout p,String value,int size,int color,boolean bold){
       TextView t=new TextView(this);t.setText(value);t.setTextSize(size);t.setTextColor(color);
       t.setPadding(0,dp(6),0,dp(9));if(bold)t.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
       p.addView(t);return t;
    }
    void space(LinearLayout parent,int h){View v=new View(this);parent.addView(v,new LinearLayout.LayoutParams(1,dp(h)));}
    LinearLayout panel(LinearLayout parent){
       LinearLayout a=new LinearLayout(this);a.setOrientation(1);a.setPadding(dp(17),dp(17),dp(17),dp(17));
       GradientDrawable gd=new GradientDrawable();gd.setColor(PANEL);gd.setCornerRadius(dp(16));a.setBackground(gd);
       LinearLayout.LayoutParams params=new LinearLayout.LayoutParams(-1,-2);params.bottomMargin=dp(14);parent.addView(a,params);return a;
    }
    void addButton(LinearLayout parent,String name,int color,Runnable action){
       Button b=new Button(this);b.setText(name);b.setAllCaps(false);b.setTextSize(14);
       b.setTextColor(color==CYAN?BG:FG);b.setTypeface(Typeface.DEFAULT,Typeface.BOLD);
       GradientDrawable gd=new GradientDrawable();gd.setColor(color);gd.setCornerRadius(dp(12));b.setBackground(gd);
       LinearLayout.LayoutParams params=new LinearLayout.LayoutParams(-1,dp(50));params.topMargin=dp(8);
       parent.addView(b,params);b.setOnClickListener(v->action.run());
    }
    @Override public void onResume(){super.onResume();handler.removeCallbacks(refresh);handler.post(refresh);}
    @Override public void onPause(){handler.removeCallbacks(refresh);super.onPause();}
    boolean installed(String p){try{getPackageManager().getPackageInfo(p,0);return true;}catch(PackageManager.NameNotFoundException e){return false;}}
    void installPcap(){Intent i=new Intent(Intent.ACTION_VIEW,Uri.parse("market://details?id="+PCAP));try{startActivity(i);}catch(Exception e){startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse("https://play.google.com/store/apps/details?id="+PCAP)));}}
    void startCapture(){
       if(!installed(PCAP)){new AlertDialog.Builder(this).setTitle("Install PCAPdroid").setMessage("Required once for non-rooted network capture.").setPositiveButton("Install",(d,w)->installPcap()).setNegativeButton("Cancel",null).show();return;}
       Intent svc=new Intent(this,CaptureService.class);svc.setAction("START");
       if(Build.VERSION.SDK_INT>=26)startForegroundService(svc);else startService(svc);
       command("start",REQ_START);
    }
    void stopCapture(){if(installed(PCAP))command("stop",REQ_STOP);else stopLocal();}
    void stopLocal(){stopService(new Intent(this,CaptureService.class));}
    void command(String action,int request){
       Intent i=new Intent(Intent.ACTION_VIEW);
       i.setClassName(PCAP,"com.emanuelef.remote_capture.activities.CaptureCtrl");
       i.putExtra("action",action);
       if(action.equals("start")){
           i.putExtra("pcap_dump_mode","udp_exporter");
           i.putExtra("collector_host","127.0.0.1");
           i.putExtra("collector_port",5123);
           i.putExtra("app_filter",GAME);
           i.putExtra("dump_extensions",false);
           i.putExtra("full_payload",true);
       }
       try{startActivityForResult(i,request);}catch(Exception e){stopLocal();Toast.makeText(this,"Cannot open PCAPdroid control: "+e.getMessage(),Toast.LENGTH_LONG).show();}
    }
    @Override protected void onActivityResult(int req,int code,Intent data){
       super.onActivityResult(req,code,data);
       if(req==REQ_START){
           if(code==RESULT_OK){
              Intent launch=getPackageManager().getLaunchIntentForPackage(GAME);
              if(launch!=null)startActivity(launch);
              else Toast.makeText(this,"Open SAOIF manually and enter Market once",Toast.LENGTH_LONG).show();
           }else{stopLocal();Toast.makeText(this,"Capture permission denied or startup failed",Toast.LENGTH_LONG).show();}
       }else if(req==REQ_STOP){
           if(code==RESULT_OK){stopLocal();Toast.makeText(this,"Capture stopped",Toast.LENGTH_SHORT).show();}
           else Toast.makeText(this,"Stop capture from PCAPdroid if necessary",Toast.LENGTH_LONG).show();
       }else if((req==REQ_PCAP||req==REQ_JSON) && code==RESULT_OK && data!=null && data.getData()!=null)export(data.getData(),req==REQ_JSON);
    }
    void saveReport(){choose(REQ_JSON,"SAOIF_probe_report.json","application/json");}
    void savePcap(){
       File f=new File(getFilesDir(),"saoif.pcap");
       if(!f.exists()||f.length()<24){Toast.makeText(this,"No packet capture available",Toast.LENGTH_LONG).show();return;}
       new AlertDialog.Builder(this).setTitle("Private packet data").setMessage("Packet captures may contain private session information. Do not post publicly.").setNegativeButton("Cancel",null).setPositiveButton("Export",(d,w)->choose(REQ_PCAP,"SAOIF_probe_capture.pcap","application/octet-stream")).show();
    }
    void choose(int code,String name,String type){Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT);i.addCategory(Intent.CATEGORY_OPENABLE);i.setType(type);i.putExtra(Intent.EXTRA_TITLE,name);startActivityForResult(i,code);}
    void export(Uri uri,boolean report){
       try(OutputStream out=getContentResolver().openOutputStream(uri)){
           if(report){
              SharedPreferences p=getSharedPreferences("market_probe",MODE_PRIVATE);
              JSONObject j=new JSONObject();j.put("app","SAOIF Market Probe v0.1.1");j.put("game",GAME);
              j.put("packets",p.getLong("packets",0));j.put("bytes",p.getLong("bytes",0));j.put("file_bytes",p.getLong("filebytes",0));
              j.put("error",p.getString("error",""));j.put("warning","No market prices decoded; session traffic may be encrypted");
              out.write(j.toString(2).getBytes(StandardCharsets.UTF_8));
           }else{
              try(FileInputStream src=new FileInputStream(new File(getFilesDir(),"saoif.pcap"))){
                 byte[] b=new byte[16384];int n;while((n=src.read(b))!=-1)out.write(b,0,n);
              }
           }
           Toast.makeText(this,"File saved",Toast.LENGTH_SHORT).show();
       }catch(Exception e){new AlertDialog.Builder(this).setTitle("Export failed").setMessage(e.toString()).setPositiveButton("OK",null).show();}
    }
}
