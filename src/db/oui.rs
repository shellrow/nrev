use anyhow::Result;
use ndb_oui::OuiDb;
use std::sync::OnceLock;

pub static OUI_DB: OnceLock<OuiDb> = OnceLock::new();

/// Initialize OUI database
pub fn init_oui_db() -> Result<()> {
    let oui_db = OuiDb::bundled();
    OUI_DB
        .set(oui_db)
        .map_err(|_| anyhow::anyhow!("Failed to set OUI_DB in OnceLock"))?;
    Ok(())
}

/// Get reference to OUI database
pub fn oui_db() -> &'static OuiDb {
    OUI_DB.get().expect("OUI_DB not initialized")
}

/// Lookup vendor name from MAC address.
pub fn lookup_vendor_name(mac_addr: &netdev::MacAddr) -> Option<String> {
    oui_db().lookup_mac(mac_addr).map(|oui| {
        oui.vendor_detail
            .clone()
            .unwrap_or_else(|| oui.vendor.clone())
    })
}
