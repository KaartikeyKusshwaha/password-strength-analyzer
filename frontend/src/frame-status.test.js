import {afterEach,expect,it,vi} from 'vitest';
import {watchPrivateFrame} from '../../companion/extension/frame-status';
afterEach(()=>vi.useRealTimers());
function runtime(){let listener;return {chrome:{runtime:{id:'ours',onMessage:{addListener:vi.fn(fn=>{listener=fn;}),removeListener:vi.fn()}}},message:(message,sender)=>listener(message,sender)};}
it('reports a missing private frame once and removes its listener',()=>{
  vi.useFakeTimers();const r=runtime(),failed=vi.fn();watchPrivateFrame(r.chrome,'request',failed);
  vi.advanceTimersByTime(7999);expect(failed).not.toHaveBeenCalled();
  vi.advanceTimersByTime(1);expect(failed).toHaveBeenCalledTimes(1);expect(r.chrome.runtime.onMessage.removeListener).toHaveBeenCalledTimes(1);
  vi.advanceTimersByTime(10000);expect(failed).toHaveBeenCalledTimes(1);
});
it('ignores wrong senders/requests and accepts only the matching private acknowledgement',()=>{
  vi.useFakeTimers();const r=runtime(),failed=vi.fn();watchPrivateFrame(r.chrome,'request',failed);
  r.message({type:'private-save-ready',id:'request'},{id:'other'});
  r.message({type:'private-save-ready',id:'different'},{id:'ours'});
  expect(r.chrome.runtime.onMessage.removeListener).not.toHaveBeenCalled();
  r.message({type:'private-save-ready',id:'request'},{id:'ours'});
  vi.advanceTimersByTime(10000);expect(failed).not.toHaveBeenCalled();
});
it('cancels the timeout on close without a late error',()=>{
  vi.useFakeTimers();const r=runtime(),failed=vi.fn(),stop=watchPrivateFrame(r.chrome,'request',failed);
  stop();stop();vi.advanceTimersByTime(10000);
  expect(failed).not.toHaveBeenCalled();expect(r.chrome.runtime.onMessage.removeListener).toHaveBeenCalledTimes(1);
});
