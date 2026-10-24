import {render,screen} from '@testing-library/react';
import {expect,it,vi} from 'vitest';
import SetupQr from './SetupQr';
const generate=vi.hoisted(()=>vi.fn(async()=> 'data:image/png;base64,fixture'));
vi.mock('qrcode',()=>({default:{toDataURL:generate}}));
it('generates an authenticator setup image locally from the provided URI',async()=>{
  render(<SetupQr uri="otpauth://totp/fixture?secret=FIXTURE"/>);
  expect(await screen.findByAltText('Private authenticator setup QR code')).toHaveAttribute('src','data:image/png;base64,fixture');
  expect(generate).toHaveBeenCalledWith('otpauth://totp/fixture?secret=FIXTURE',expect.objectContaining({width:220}));
});
