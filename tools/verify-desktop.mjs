// Import and call with a connected Playwright page; local dashboard must run.
// Desktop only. Uses local sample scans and controlled API failures; no TLS scan.
export default async function verifyDesktop(page) {
  const assert = (value, message) => { if (!value) throw Error(message); };
  await page.setViewportSize({width:1440,height:1000});
  await page.emulateMedia({reducedMotion:'reduce'});
  await page.goto('http://127.0.0.1:8765');
  await page.locator('#results-summary').waitFor({timeout:5000});
  const entry = await page.evaluate(() => ({
    scrollY,
    formTop:document.querySelector('#scan-console').getBoundingClientRect().top,
    submitBottom:[...document.querySelectorAll('button')].find(e=>e.textContent.includes('Scan Repository')).getBoundingClientRect().bottom,
  }));
  assert(entry.scrollY===0 && entry.submitBottom<1000,'Initial demo moved viewport or scan form is below first screen');

  const opener=page.getByRole('button').filter({hasText:'View Evidence & Migration'}).first();
  await opener.click();
  await page.waitForTimeout(150); // Verify settled focus after native showModal.
  assert(await page.getByRole('dialog').getAttribute('aria-modal')==='true','Modal semantics missing');
  assert(await page.getByRole('dialog').getAttribute('aria-labelledby')==='evidence-dialog-title','Modal title missing');
  assert(await page.evaluate(()=>document.activeElement.getAttribute('aria-label')==='Close evidence inspector'),'Initial focus missing');
  await page.keyboard.press('Shift+Tab');
  assert(await page.evaluate(()=>document.activeElement.textContent.trim()==='Close Inspector'),'Reverse Tab containment missing');
  await page.keyboard.press('Tab');
  assert(await page.evaluate(()=>document.activeElement.getAttribute('aria-label')==='Close evidence inspector'),'Forward Tab containment missing');
  await page.evaluate(()=>document.querySelector('header button').focus());
  assert(await page.evaluate(()=>document.querySelector('#root').inert && document.body.style.overflow==='hidden' && !!document.activeElement.closest('dialog')),'Background is interactive or scroll lock missing');
  await page.keyboard.press('Escape');
  assert(await opener.evaluate(e=>document.activeElement===e),'Opener focus not restored');
  assert(await page.evaluate(()=>!document.querySelector('#root').inert && document.body.style.overflow===''),'Modal cleanup missing');

  // First demo asset has multiple inventory findings. Unknown trust is omitted.
  await page.locator('#context-data_lifetime_years').fill('30');
  await page.locator('#context-migration_years').fill('0');
  const updated=page.waitForResponse(r=>r.url().endsWith('/api/reassess'),{timeout:5000});
  await page.getByRole('button',{name:'Confirm context & reassess'}).click();
  const response=await updated, request=response.request().postDataJSON(), result=await response.json();
  assert(response.status()===200,'Reassessment failed');
  assert(request.overrides.length===3 && request.overrides.every(o=>o.migration_years===0 && !('trust_lifetime_years' in o)),'Asset IDs, zero or blank omission incorrect');
  assert(result.metadata.scan_id!==request.scan_id && result.metadata.parent_scan_id===request.scan_id,'Reassessment is not a new parent-linked report');
  await page.waitForFunction(()=>document.activeElement.id==='results-summary',{timeout:5000});
  assert(await page.locator('#context-migration_years').inputValue()==='0','Confirmed zero not displayed');
  const old=await page.locator('#results-summary').innerText();
  await page.route('**/api/reassess',route=>route.fulfill({status:409,contentType:'application/json',body:JSON.stringify({error:'Controlled missing snapshot'})}));
  try {
    await page.locator('#context-data_lifetime_years').fill('31');
    await page.getByRole('button',{name:'Confirm context & reassess'}).click();
    await page.getByRole('alert').filter({hasText:'Controlled missing snapshot'}).waitFor({timeout:5000});
    assert(await page.locator('#results-summary').innerText()===old,'Failed reassessment replaced report');
  } finally { await page.unroute('**/api/reassess'); }

  await page.getByRole('button',{name:/Scan Repository/}).click();
  await page.waitForFunction(()=>document.activeElement.id==='results-summary',{timeout:5000});
  const scanned=await page.locator('#results-summary').innerText();
  await page.getByLabel('Repository or configuration file path').fill('/definitely/missing-task5');
  await page.getByRole('button',{name:/Scan Repository/}).click();
  await page.getByRole('alert').waitFor({timeout:5000});
  assert(await page.locator('#results-summary').innerText()===scanned,'Failed scan replaced report');

  await page.locator('.cyber-nav-links').getByRole('link',{name:'Horizon lab'}).click();
  assert(await page.locator('#horizon-lab').evaluate(e=>e.closest('details').open && e.getBoundingClientRect().height>0),'Navigation did not open exploration');
  const buttonFonts=await page.locator('.optional-exploration button:visible').evaluateAll(els=>({count:els.length,min:Math.min(...els.map(e=>parseFloat(getComputedStyle(e).fontSize)))}));
  assert(buttonFonts.min>=12,'Optional interaction controls are too small');
  await page.locator('.intel-legend button').filter({hasText:'critical'}).click();
  assert((await page.locator('.intel-filter-notice').innerText()).includes('critical'),'Severity chart interaction failed');
  await page.locator('.cyber-nav-links').getByRole('link',{name:'Incident'}).click();
  assert((await page.locator('.incident-timeline').innerText()).includes('22:59 UTC'),'Initial OneCRL chronology missing');
  return {entry,dialog:'passed',reassessment:{count:request.overrides.length,newReport:true,zero:true,failurePreserved:true},scan:'success/failure passed',buttonFonts,navigation:'passed'};
}
