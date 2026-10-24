import React from 'react';
import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import OwnerPromotion from './OwnerPromotion';
import {api} from './api';
vi.mock('./api',()=>({api:vi.fn(async()=>({ok:true}))}));
it('makes workspace elevation explicit and clears the fresh approval credentials',async()=>{
 const onChanged=vi.fn();render(<OwnerPromotion members={[{id:'a'.repeat(24),role:'owner',email:'owner@example.test'},{id:'b'.repeat(24),role:'reviewer',email:'receiver@example.test'}]} onChanged={onChanged}/>);
 fireEvent.change(screen.getByLabelText('Member to promote'),{target:{value:'b'.repeat(24)}});
 fireEvent.change(screen.getByLabelText('Current account password'),{target:{value:'fixture-only'}});fireEvent.change(screen.getByLabelText('Unused MFA or recovery code'),{target:{value:'123456'}});
 fireEvent.click(screen.getByLabelText('I approve granting this person full workspace owner access.'));fireEvent.click(screen.getByRole('button',{name:'Promote receiving owner'}));
 await waitFor(()=>expect(api).toHaveBeenCalledWith('/members/'+'b'.repeat(24)+'/promote-owner',{confirmed:true,password:'fixture-only',code:'123456'}));
 expect(screen.getByLabelText('Current account password')).toHaveValue('');await waitFor(()=>expect(onChanged).toHaveBeenCalled());
});
