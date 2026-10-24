import {useEffect,useState} from 'react';
export default function SetupQr({uri}) {
  const [image,setImage]=useState(''),[error,setError]=useState(false);
  useEffect(()=>{let alive=true;setImage('');setError(false);if(uri)import('qrcode').then(module=>module.default.toDataURL(uri,{width:220,margin:2,errorCorrectionLevel:'M'})).then(value=>{if(alive)setImage(value);}).catch(()=>{if(alive)setError(true);});return()=>{alive=false;};},[uri]);
  return image?<img width={220} height={220} src={image} alt="Private authenticator setup QR code"/>:error?<p role="alert">Could not generate the local setup QR code. The setup key remains available below.</p>:null;
}
