import {mergeConfig} from 'vite';
import base from './vite.config';
export default mergeConfig(base,{server:{host:'127.0.0.1',port:18222,strictPort:true,proxy:{'/api':'http://127.0.0.1:18221'}}});
