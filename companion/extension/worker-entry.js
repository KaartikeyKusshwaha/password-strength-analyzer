import {createSiteMonitor} from './site-monitor';
import './public/background';
globalThis.sentinelMonitor=createSiteMonitor(chrome);
globalThis.sentinelMonitorProtocol='sentinel-site-monitor/v1';
globalThis.sentinelMonitor.install();
