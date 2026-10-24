import {useEffect,useState} from 'react';
import {Bell} from 'lucide-react';
import {api} from './api';
export default function WatchIndicator({open}){
  const [unread,setUnread]=useState(null);
  useEffect(()=>{let alive=true;async function load(){try{const value=await api('/notifications');if(alive)setUnread(Number.isInteger(value.unread)?value.unread:null);}catch{if(alive)setUnread(null);}}load();const timer=setInterval(load,15000);return()=>{alive=false;clearInterval(timer);};},[]);
  return <button className="icon-button" aria-label={unread===null?'Open alerts; count unavailable':`Open alerts; ${unread} unread`} onClick={open}><Bell size={17}/>{unread>0&&<span className="badge">{unread}</span>}</button>;
}
