(function(){
'use strict';
var rand=function(a,b){return a+Math.random()*(b-a)};
var clamp=function(v,a,b){return Math.max(a,Math.min(b,v))};
var mod=function(v,n){return((v%n)+n)%n};
var TAU=Math.PI*2;

var reduced=matchMedia('(prefers-reduced-motion: reduce)');
function isDark(){return document.documentElement.getAttribute('data-theme')==='dark'}

var raf=0,last=0,time=0,scenes=[];
var pointer={x:200,y:300};

function eyeMarkup(id){
  return '<svg class="eye-svg" viewBox="0 0 140 140">'
    +'<defs><clipPath id="'+id+'"><path data-opening/></clipPath></defs>'
    +'<path class="eye-paper" d="M70 8 C105 5 128 32 130 67 C133 102 109 130 73 131 C36 134 10 110 9 76 C7 43 27 11 61 8Z" stroke="currentColor" stroke-width="5"/>'
    +'<g clip-path="url(#'+id+')"><g data-pupil><rect x="43" y="49" width="54" height="45" rx="12" fill="currentColor"/></g></g>'
    +'<path data-upper fill="none" stroke="currentColor" stroke-width="6"/>'
    +'<path data-lower fill="none" stroke="currentColor" stroke-width="6"/>'
    +'<path d="M29 24 L39 18" stroke="currentColor" stroke-width="4" stroke-linecap="round"/>'
    +'</svg>';
}

var bigEyeEl=document.getElementById('big-eye');
var smallEyeEl=document.getElementById('small-eye');
if(bigEyeEl)bigEyeEl.innerHTML=eyeMarkup('big-clip');
if(smallEyeEl)smallEyeEl.innerHTML=eyeMarkup('small-clip');

var eyes=[].slice.call(document.querySelectorAll('.eye-svg')).map(function(svg){
  return{svg:svg,pupil:svg.querySelector('[data-pupil]'),opening:svg.querySelector('[data-opening]'),upper:svg.querySelector('[data-upper]'),lower:svg.querySelector('[data-lower]'),x:0,y:0,next:rand(1.4,3),start:null};
});

function drawEyes(dt){
  for(var ei=0;ei<eyes.length;ei++){
    var e=eyes[ei];
    var r=e.svg.getBoundingClientRect();
    var dx=pointer.x-r.left-r.width/2,dy=pointer.y-r.top-r.height*0.52;
    var d=Math.hypot(dx,dy),strength=Math.min(d/180,1);
    var smooth=reduced.matches?1:1-Math.exp(-dt*15);
    e.x+=((d?dx/d*19*strength:0)-e.x)*smooth;
    e.y+=((d?dy/d*3*strength:0)-e.y)*smooth;
    e.pupil.setAttribute('transform','translate('+e.x+' '+e.y+')');
    var open=1;
    if(!reduced.matches){
      if(e.start===null&&time>=e.next)e.start=time;
      if(e.start!==null){var p=(time-e.start)/0.16;if(p>=1){e.start=null;e.next=time+rand(1.8,3.8)}else open=Math.max(0.02,Math.abs(p*2-1))}
    }
    var u=72-11*open,l=72+14*open;
    e.upper.setAttribute('d','M13 '+u+' Q70 '+(u-6*open)+' 127 '+u);
    e.lower.setAttribute('d','M14 '+l+' Q70 '+(l-7*open)+' 126 '+l);
    e.opening.setAttribute('d','M13 '+u+' Q70 '+(u-6*open)+' 127 '+u+' L126 '+l+' Q70 '+(l-7*open)+' 14 '+l+'Z');
  }
}

var cloud=new Path2D('M-95 20 Q-120 17 -105 10 Q-120 -8 -104 -17 Q-91 -25 -82 -9 Q-90 -37 -65 -37 Q-57 -66 -30 -48 Q-8 -76 12 -51 Q40 -68 48 -40 Q73 -43 73 -18 Q94 -25 100 -5 Q120 -4 108 10 Q137 15 120 22 Q80 27 40 22 Q0 30 -37 23 Q-75 30 -95 20 M-79 -8 Q-73 -23 -59 -12 M-35 -32 Q-20 -46 -8 -29 M18 -39 Q36 -46 39 -29 M59 -13 Q72 -22 80 -7 M-62 16 Q-47 2 -35 14 M0 19 Q15 4 26 17 M66 17 Q78 8 89 18');

function Shape(){this.lines=[];this.line=null;this.x=0;this.y=0}
Shape.prototype.m=function(x,y){this.line=[];this.lines.push(this.line);this.line.push([x,y]);this.x=x;this.y=y;return this};
Shape.prototype.l=function(x,y){var sx=this.x,sy=this.y;for(var i=1;i<=6;i++)this.line.push([sx+(x-sx)*i/6,sy+(y-sy)*i/6]);this.x=x;this.y=y;return this};
Shape.prototype.c=function(ax,ay,bx,by,x,y){var sx=this.x,sy=this.y;for(var i=1;i<=12;i++){var t=i/12,u=1-t;this.line.push([u*u*u*sx+3*u*u*t*ax+3*u*t*t*bx+t*t*t*x,u*u*u*sy+3*u*u*t*ay+3*u*t*t*by+t*t*t*y])}this.x=x;this.y=y;return this};
Shape.prototype.q=function(ax,ay,x,y){return this.c(this.x+(ax-this.x)*2/3,this.y+(ay-this.y)*2/3,x+(ax-x)*2/3,y+(ay-y)*2/3,x,y)};

var dolphinShape=new Shape().m(1.28,.02).q(1.10,-.04,.94,-.07).c(.78,-.34,.45,-.43,.04,-.36).q(-.10,-.45,-.24,-.70).q(-.36,-.77,-.38,-.33).c(-.76,-.29,-1.05,-.14,-1.29,-.015).q(-1.49,-.20,-1.64,-.28).q(-1.59,-.07,-1.43,.025).q(-1.60,.11,-1.65,.28).q(-1.43,.23,-1.27,.10).c(-.88,.16,-.49,.35,.04,.28).q(.52,.25,.91,.12).q(1.12,.19,1.29,.12).q(1.38,.07,1.28,.02).m(.12,.24).q(-.07,.57,-.34,.56).q(-.23,.35,-.12,.26).m(.91,.12).q(1.08,.17,1.26,.11);
var fishShape=new Shape().m(1,.04).c(.50,-.49,-.18,-.45,-.67,0).l(-1.14,-.34).q(-1.02,0,-1.17,.34).l(-.64,.14).q(.28,.49,1,.04).m(.02,-.30).q(-.17,-.55,-.31,-.32).m(.06,.05).q(-.18,.24,-.28,.10);

function Ocean(canvas,mini){
  this.canvas=canvas;this.c=canvas.getContext('2d');this.mini=!!mini;
  this.w=1;this.h=1;this.creatures=[];this.clouds=[];this.particles=[];
  var self=this;
  this.observer=new ResizeObserver(function(){self.resize();schedule()});
  this.observer.observe(canvas);
}
Ocean.prototype.surface=function(x,t){
  if(t===undefined)t=time;
  return this.h*(this.mini?0.68:0.56)+Math.sin(x*0.009+t*0.75)*(this.mini?3:6)+Math.sin(x*0.018-t*0.42)*(this.mini?1.5:3);
};
Ocean.prototype.resize=function(){
  var r=this.canvas.getBoundingClientRect();
  if(!r.width||!r.height)return;
  this.w=r.width;this.h=r.height;
  var dpr=Math.min(devicePixelRatio||1,2);
  this.canvas.width=Math.round(this.w*dpr);this.canvas.height=Math.round(this.h*dpr);
  this.c.setTransform(dpr,0,0,dpr,0,0);
  var count=this.mini?7:12;
  var self=this;
  this.creatures=Array.from({length:count},function(_,i){
    var dolph=i<(self.mini?2:3);
    var size=self.mini?(dolph?19:rand(11,14)):(dolph?rand(26,34):rand(15,21));
    var height=self.mini?(dolph?28:17):(dolph?rand(44,64):rand(22,32));
    var depth=self.mini?(dolph?36:rand(18,28)):(dolph?Math.min(rand(70,95),self.h*0.24):rand(24,Math.max(30,self.h*0.18)));
    var airDuration=dolph?rand(1.0,1.25):rand(0.75,1.0);
    var diveDuration=depth*Math.PI*airDuration/(4*height);
    return{dolphin:dolph,jumper:dolph||i%2===0,size:size,height:height,depth:depth,airDuration:airDuration,diveDuration:diveDuration,duration:airDuration+diveDuration,phase:rand(0,airDuration+diveDuration),x:rand(0,self.w),direction:Math.random()>0.5?1:-1,speed:self.mini?(dolph?85:rand(52,68)):(dolph?rand(135,175):rand(72,98)),seed:rand(0,TAU),trail:0,previousDepth:null,spine:[],visits:{air:0,water:0}};
  });
  this.clouds=Array.from({length:this.mini?3:4},function(_,i){
    return{x:self.w*(i+0.25)/(self.mini?3:4),y:self.h*(self.mini?0.16+i*0.07:0.08+i*0.09),scale:self.mini?0.17+i*0.025:0.38+i*0.06,speed:self.mini?7+i*1.5:11+i*2,phase:i*2.1};
  });
  this.particles=[];
};
Ocean.prototype.add=function(p){if(this.particles.length<(this.mini?90:260))this.particles.push(p)};
Ocean.prototype.splash=function(x,y,entry){
  var scale=this.mini?0.5:1.0;
  for(var i=0;i<(entry?10:6);i++)this.add({type:'drop',x:x,y:y,vx:rand(-100,100)*scale,vy:rand(-140,-45)*scale,age:0,life:rand(0.55,0.95),scale:scale});
  for(var j=0;j<2;j++)this.add({type:'ripple',x:x,y:y+j*3,age:0,life:1.9+j*0.25,scale:scale*0.85});
};
Ocean.prototype.trajectory=function(f,t){
  if(!f.jumper)return{depth:f.depth+Math.sin(t*0.9+f.seed)*(this.mini?3:7),air:false};
  var q=mod(t+f.phase,f.duration);
  if(q<f.airDuration){var u=q/f.airDuration;return{depth:-4*f.height*u*(1-u),air:true}}
  var u2=(q-f.airDuration)/f.diveDuration;return{depth:f.depth*Math.sin(Math.PI*u2),air:false};
};
Ocean.prototype.path=function(f,t){var x=f.x+f.direction*f.speed*(t-time);return{x:x,y:this.surface(x,t)+this.trajectory(f,t).depth}};
Ocean.prototype.buildSpine=function(f){
  var segments=64,length=3.15*f.size,step=length/segments;
  var t=time+1.4*f.size/f.speed;var points=f.spine;points.length=0;
  for(var i=0;i<=segments;i++){
    var local=1.4-i*3.15/segments;var base=this.path(f,t);
    var tailness=clamp((1.05-local)/2.7,0,1),midsection=Math.sin(clamp((1.4-local)/3.15,0,1)*Math.PI);
    var air=this.trajectory(f,t).air;var frequency=f.dolphin?8.3:12;
    var amplitude=f.dolphin?(0.10*midsection+0.27*tailness*tailness):(0.035*midsection+0.17*tailness*tailness);
    var stroke=Math.sin(time*frequency+local*2.5+f.seed)*f.size*amplitude*(air?0.4:1);
    base.y+=stroke;points.push(base);
    var before=this.path(f,t-0.004),after=this.path(f,t+0.004);
    var velocity=Math.hypot((after.x-before.x)/0.008,(after.y-before.y)/0.008);
    t-=step/Math.max(velocity,1);
  }
  for(var j=0;j<points.length;j++){
    var a=points[Math.max(0,j-1)],b=points[Math.min(points.length-1,j+1)];
    var dx=a.x-b.x,dy=a.y-b.y,n=Math.hypot(dx,dy)||1;
    points[j].nx=-dy/n*f.direction;points[j].ny=dx/n*f.direction;
  }
};
Ocean.prototype.map=function(f,x,y){
  var index=clamp((1.4-x)/3.15*64,0,64),i=Math.min(63,Math.floor(index)),mix=index-i;
  var a=f.spine[i],b=f.spine[i+1];
  var normalX=a.nx+(b.nx-a.nx)*mix,normalY=a.ny+(b.ny-a.ny)*mix;
  var norm=Math.hypot(normalX,normalY)||1;normalX/=norm;normalY/=norm;
  var width=f.dolphin?1:1-0.10*Math.sin(time*12+f.seed);
  return{x:a.x+(b.x-a.x)*mix+normalX*y*f.size*width,y:a.y+(b.y-a.y)*mix+normalY*y*f.size*width};
};
Ocean.prototype.drawCreature=function(f){
  this.buildSpine(f);var c=this.c;var dk=isDark();
  var ink=this.mini||dk?'#fffef1':'#252d22';
  c.save();c.strokeStyle=ink;c.fillStyle=ink;
  c.globalAlpha=this.mini?0.84:dk?0.82:0.68;c.lineWidth=this.mini?1.65:2.2;
  c.beginPath();
  var shape=f.dolphin?dolphinShape:fishShape;
  for(var li=0;li<shape.lines.length;li++){
    var line=shape.lines[li];
    for(var pi=0;pi<line.length;pi++){
      var pt=this.map(f,line[pi][0],line[pi][1]);
      if(pi)c.lineTo(pt.x,pt.y);else c.moveTo(pt.x,pt.y);
    }
  }
  c.stroke();
  var eye=this.map(f,f.dolphin?0.73:0.55,f.dolphin?-0.13:-0.09);
  c.beginPath();c.arc(eye.x,eye.y,Math.max(0.75,f.size*0.03),0,TAU);c.fill();
  c.restore();
};
Ocean.prototype.drawClouds=function(dt){
  var c=this.c;var dk=isDark();
  for(var ci=0;ci<this.clouds.length;ci++){
    var item=this.clouds[ci];
    if(!reduced.matches)item.x+=item.speed*dt;
    var margin=140*item.scale;if(item.x-margin>this.w)item.x=-margin;
    c.save();c.translate(item.x,item.y+Math.sin(time*0.28+item.phase)*(this.mini?2.5:5));
    c.scale(item.scale,item.scale);
    c.strokeStyle=this.mini||dk?'#fffef1':'#384134';
    var bloom=reduced.matches?0.65:0.5+0.5*Math.sin(time*0.8+item.phase);
    c.globalAlpha=this.mini?0.28+bloom*0.38:0.32+bloom*0.24;
    c.lineWidth=this.mini?3.2:2.2;c.stroke(cloud);c.restore();
  }
};
Ocean.prototype.drawSea=function(){
  var c=this.c;var dk=isDark();var ink=this.mini||dk?'#fffef1':'#252d22';
  c.beginPath();c.moveTo(0,this.surface(0));
  for(var x=0;x<=this.w+10;x+=10)c.lineTo(x,this.surface(x));
  c.lineTo(this.w,this.h);c.lineTo(0,this.h);c.closePath();
  c.fillStyle=this.mini?'#ffffff14':dk?'#b7dfca14':'#658c7922';c.fill();

  var segments=this.mini?1:Math.max(2,Math.ceil(this.w/220)),span=this.w/segments;
  for(var i=0;i<segments;i++){
    var sx=i*span;c.save();c.translate(sx,this.surface(sx));
    c.scale(span/210,this.mini?0.62:1);c.strokeStyle=ink;
    c.globalAlpha=this.mini?0.72:dk?0.64:0.54;c.lineWidth=1.9;
    var flex=Math.sin(time*0.7+i)*3;
    c.beginPath();
    c.moveTo(-6,0);c.bezierCurveTo(32,-18+flex,54,-12,87,-5);
    c.bezierCurveTo(126,5,154,13+flex,182,5);c.bezierCurveTo(210,-3,211,-24,193,-22);
    c.bezierCurveTo(180,-20,192,-12,200,-15);
    c.moveTo(-5,8);c.bezierCurveTo(31,-4,58,-2+flex,91,6);
    c.bezierCurveTo(124,14,154,22,175,18);
    c.moveTo(65,7);c.bezierCurveTo(89,10,88,30+flex,72,27);
    c.bezierCurveTo(65,25,65,21,69,20);
    c.stroke();c.restore();
  }

  if(!reduced.matches&&Math.random()<(this.mini?0.012:0.016)){
    var rx=rand(10,this.w-10);
    this.add({type:'ripple',x:rx,y:this.surface(rx)+rand(-1,2),age:0,life:rand(1.8,2.3),scale:this.mini?0.42:0.75});
  }
};
Ocean.prototype.drawParticles=function(dt){
  var c=this.c;var dk=isDark();var ink=this.mini||dk?'#fffef1':'#252d22';
  for(var i=this.particles.length-1;i>=0;i--){
    var p=this.particles[i];
    if(!reduced.matches)p.age+=dt;
    if(p.age>=p.life){this.particles.splice(i,1);continue}
    c.strokeStyle=ink;
    c.beginPath();
    if(p.type==='drop'){
      c.globalAlpha=(1-p.age/p.life)*(this.mini?0.65:dk?0.58:0.48);c.lineWidth=1.2;
      if(!reduced.matches){p.vy+=230*p.scale*dt;p.x+=p.vx*dt;p.y+=p.vy*dt}
      c.moveTo(p.x,p.y);c.lineTo(p.x-p.vx*0.03,p.y-p.vy*0.03);
    }else if(p.type==='ripple'){
      var alpha=(1-p.age/p.life);
      c.globalAlpha=alpha*(this.mini?0.36:dk?0.32:0.26);
      c.lineWidth=Math.max(0.5,(1.35-(p.age/p.life)*0.85)*p.scale);
      c.ellipse(p.x,p.y,(6+p.age*42)*p.scale,(2.2+p.age*8.5)*p.scale,0,0,TAU);
    }else{
      c.globalAlpha=(1-p.age/p.life)*(this.mini?0.65:dk?0.60:0.48);c.lineWidth=1.1;
      if(!reduced.matches)p.y-=dt*11;
      c.arc(p.x,p.y,(1.4+p.age*1.5)*p.scale,0,TAU);
    }
    c.stroke();
  }
  c.globalAlpha=1;
};
Ocean.prototype.draw=function(dt){
  var c=this.c;c.clearRect(0,0,this.w,this.h);c.lineCap='round';c.lineJoin='round';
  this.drawClouds(dt);this.drawSea();
  for(var fi=0;fi<this.creatures.length;fi++){
    var f=this.creatures[fi];
    if(!reduced.matches)f.x+=f.direction*f.speed*dt;
    var margin=f.size*3;
    if(f.x>this.w+margin)f.x=-margin;if(f.x<-margin)f.x=this.w+margin;
    var pose=this.trajectory(f,time),water=this.surface(f.x);
    if(!reduced.matches&&f.previousDepth!==null){
      if(f.previousDepth<0&&pose.depth>=0)this.splash(f.x,water,true);
      else if(f.previousDepth>=0&&pose.depth<0)this.splash(f.x,water,false);
    }
    f.previousDepth=pose.depth;
    if(pose.air)f.visits.air++;else f.visits.water++;
    if(!reduced.matches&&pose.depth>5){
      f.trail+=dt;
      if(f.trail>0.25){
        var tail=this.path(f,time-1.3*f.size/f.speed);
        this.add({type:'bubble',x:tail.x,y:tail.y,age:0,life:1.8,scale:this.mini?0.5:1});
        f.trail=0;
      }
    }
    this.drawCreature(f);
  }
  this.drawParticles(dt);
};

function frame(timestamp){
  raf=0;if(document.hidden)return;
  var dt=last?Math.min((timestamp-last)/1000,0.035):1/60;
  last=timestamp;if(!reduced.matches)time+=dt;
  for(var i=0;i<scenes.length;i++)scenes[i].draw(dt);
  drawEyes(dt);
  if(!reduced.matches)raf=requestAnimationFrame(frame);
}
function schedule(){if(!raf&&!document.hidden)raf=requestAnimationFrame(frame)}

var seaCanvas=document.getElementById('sea');
var miniCanvas=document.getElementById('mini');
if(seaCanvas)scenes.push(new Ocean(seaCanvas,false));
if(miniCanvas)scenes.push(new Ocean(miniCanvas,true));
for(var i=0;i<scenes.length;i++)scenes[i].resize();
last=0;schedule();

window.addEventListener('pointermove',function(e){pointer.x=e.clientX;pointer.y=e.clientY;if(reduced.matches)schedule()},{passive:true});
document.addEventListener('visibilitychange',function(){cancelAnimationFrame(raf);raf=0;last=0;schedule()});
reduced.addEventListener('change',function(){last=0;schedule()});
})();
