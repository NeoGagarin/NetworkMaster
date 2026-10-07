use crate::{AppError, Result};
use nm_core::{
    CredentialProfileId, Device, DeviceFamily, DeviceId, EnrollmentSource, ManagementAddress, Site,
    SiteId, Vendor,
};
use nm_store::{
    repo::{DeviceFilter, DeviceRepo, ProfileRepo, SiteRepo},
    Db,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Read;

#[derive(Debug, Default, Serialize)]
pub struct ImportReport {
    pub added: usize,
    pub skipped_duplicates: usize,
    pub errors: Vec<(u64, String)>,
}
pub struct InventoryService<'a> {
    db: &'a Db,
}
impl<'a> InventoryService<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }
    pub fn site(&self, name: &str) -> Result<SiteId> {
        let repo = SiteRepo::new(self.db);
        if let Ok(id) = name.parse::<SiteId>() {
            return repo
                .get(id)?
                .map(|s| s.id)
                .ok_or_else(|| AppError::Invalid("site does not exist".into()));
        }
        if let Some(site) = repo.list()?.into_iter().find(|s| s.name == name) {
            return Ok(site.id);
        }
        if name.trim().is_empty() {
            return Err(AppError::Invalid("site name is empty".into()));
        }
        let site = Site {
            id: SiteId::new(),
            name: name.into(),
            notes: String::new(),
            max_distance_m: None,
        };
        repo.insert(&site)?;
        Ok(site.id)
    }
    pub fn add_manual(
        &self,
        addr: ManagementAddress,
        family: DeviceFamily,
        name: Option<String>,
        site: Option<&str>,
    ) -> Result<Device> {
        self.check_duplicate(&addr, family)?;
        let site = site.map(|s| self.site(s)).transpose()?;
        let device = Device {
            id: DeviceId::new(),
            display_name: name
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| addr.to_string()),
            management: addr,
            vendor: if family == DeviceFamily::Unknown {
                Vendor::Unknown
            } else {
                Vendor::Ubiquiti
            },
            family,
            role: None,
            site,
            credential_profile: None,
            source: EnrollmentSource::Manual,
            enrolled: false,
            ssh_legacy_ok: false,
            interface_roles: std::collections::BTreeMap::default(),
            tags: vec![],
        };
        DeviceRepo::new(self.db).insert(&device)?;
        Ok(device)
    }
    fn check_duplicate(&self, addr: &ManagementAddress, family: DeviceFamily) -> Result<()> {
        if DeviceRepo::new(self.db)
            .list(&DeviceFilter::default())?
            .iter()
            .any(|d| {
                d.management.host == addr.host
                    && d.management.port.unwrap_or(d.family.default_port())
                        == addr.port.unwrap_or(family.default_port())
            })
        {
            return Err(AppError::Duplicate);
        }
        Ok(())
    }
    pub fn add_candidate(&self, device: &Device) -> Result<bool> {
        if device.enrolled {
            return Err(AppError::Invalid(
                "discovery must produce candidates".into(),
            ));
        }
        match self.check_duplicate(&device.management, device.family) {
            Err(AppError::Duplicate) => return Ok(false),
            other => other?,
        }
        DeviceRepo::new(self.db).insert(device)?;
        Ok(true)
    }
    pub fn import_csv(&self, reader: impl Read) -> Result<ImportReport> {
        let mut csv = csv::ReaderBuilder::new()
            .trim(csv::Trim::All)
            .from_reader(reader);
        let headers = csv
            .headers()
            .map_err(|e| AppError::Invalid(e.to_string()))?
            .clone();
        let fields = ["address", "name", "family", "site"];
        let indexes = fields.map(|name| headers.iter().position(|s| s == name));
        if indexes.iter().any(Option::is_none) || headers.len() != 4 {
            return Err(AppError::Invalid(
                "CSV header must contain address,name,family,site".into(),
            ));
        }
        let indexes = indexes.map(Option::unwrap);
        let mut report = ImportReport::default();
        for record in csv.records() {
            let row = match record {
                Ok(row) => row,
                Err(e) => {
                    report
                        .errors
                        .push((e.position().map_or(0, csv::Position::line), e.to_string()));
                    continue;
                }
            };
            let line = row.position().map_or(0, csv::Position::line);
            let result = (|| {
                let addr = row[indexes[0]].parse().map_err(AppError::Invalid)?;
                let family = row[indexes[2]].parse().map_err(AppError::Invalid)?;
                let site = &row[indexes[3]];
                self.add_manual(
                    addr,
                    family,
                    Some(row[indexes[1]].into()),
                    (!site.is_empty()).then_some(site),
                )
            })();
            match result {
                Ok(_) => report.added += 1,
                Err(AppError::Duplicate) => report.skipped_duplicates += 1,
                Err(e) => report.errors.push((line, e.to_string())),
            }
        }
        Ok(report)
    }
    fn mutate(&self, ids: &[DeviceId], f: impl Fn(&mut Device)) -> Result<()> {
        let repo = DeviceRepo::new(self.db);
        let mut devices = ids
            .iter()
            .map(|id| repo.get(*id)?.ok_or(nm_store::StoreError::NotFound))
            .collect::<nm_store::Result<Vec<_>>>()?;
        for device in &mut devices {
            f(device);
            repo.update(device)?;
        }
        Ok(())
    }
    pub fn enroll(&self, ids: &[DeviceId]) -> Result<()> {
        self.mutate(ids, |d| d.enrolled = true)
    }
    pub fn unenroll(&self, ids: &[DeviceId]) -> Result<()> {
        self.mutate(ids, |d| d.enrolled = false)
    }
    pub fn assign_profile(
        &self,
        ids: &[DeviceId],
        profile: Option<CredentialProfileId>,
    ) -> Result<()> {
        if let Some(id) = profile {
            if ProfileRepo::new(self.db).get(id)?.is_none() {
                return Err(AppError::Invalid("profile does not exist".into()));
            }
        }
        self.mutate(ids, |d| d.credential_profile = profile)
    }
    pub fn set_site(&self, ids: &[DeviceId], site: Option<SiteId>) -> Result<()> {
        if let Some(id) = site {
            if SiteRepo::new(self.db).get(id)?.is_none() {
                return Err(AppError::Invalid("site does not exist".into()));
            }
        }
        self.mutate(ids, |d| d.site = site)
    }
    pub fn allow_legacy(&self, ids: &[DeviceId], allowed: bool) -> Result<()> {
        self.mutate(ids, |d| d.ssh_legacy_ok = allowed)
    }
    pub fn set_role(&self, ids: &[DeviceId], role: Option<nm_core::DeviceRole>) -> Result<()> {
        self.mutate(ids, |d| d.role = role)
    }
    pub fn remove(&self, ids: &[DeviceId]) -> Result<()> {
        let repo = DeviceRepo::new(self.db);
        for id in ids {
            if repo.get(*id)?.is_none() {
                return Err(nm_store::StoreError::NotFound.into());
            }
        }
        for id in ids {
            repo.delete(*id)?;
        }
        Ok(())
    }
    pub fn inventory_hash(&self) -> Result<[u8; 32]> {
        Ok(inventory_hash(&DeviceRepo::new(self.db).list(
            &DeviceFilter {
                enrolled: Some(true),
                ..DeviceFilter::default()
            },
        )?))
    }
}
pub fn inventory_hash(devices: &[Device]) -> [u8; 32] {
    let mut rows: Vec<_> = devices
        .iter()
        .filter(|d| d.enrolled)
        .map(|d| {
            format!(
                "{}\0{}\0{}\n",
                d.id,
                d.management.host,
                d.management.port.unwrap_or(d.family.default_port())
            )
        })
        .collect();
    rows.sort_unstable();
    Sha256::digest(rows.concat().as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn csv_validation_duplicates_and_stable_hash() {
        let db = Db::open_in_memory().unwrap();
        let svc = InventoryService::new(&db);
        let report = svc.import_csv("address,name,family,site\n192.0.2.1,\"Tower, AP\",airos,Tower\n192.0.2.1:22,Duplicate,airos,Tower\n192.0.2.2,Station,auto,Tower\n192.0.2.3,Bad,nope,Tower\n".as_bytes()).unwrap();
        assert_eq!(
            (report.added, report.skipped_duplicates, report.errors.len()),
            (2, 1, 1)
        );
        assert_eq!(report.errors[0].0, 5);
        assert!(svc.import_csv("address,name\na,b\n".as_bytes()).is_err());
        let mut devices = DeviceRepo::new(&db).list(&DeviceFilter::default()).unwrap();
        svc.enroll(&devices.iter().map(|d| d.id).collect::<Vec<_>>())
            .unwrap();
        for d in &mut devices {
            d.enrolled = true;
        }
        let hash = inventory_hash(&devices);
        devices.reverse();
        assert_eq!(hash, inventory_hash(&devices));
        assert_eq!(hash, svc.inventory_hash().unwrap());
        assert_eq!(SiteRepo::new(&db).list().unwrap().len(), 1);
    }
}
