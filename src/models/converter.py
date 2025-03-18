import re
from typing import List

from osv import Bug

from src.models.errata import *
from src.settings import collection_name_to_ecosystem


def OSVBugFromErrataUpdate(errata_update: ErrataUpdateXMLView, ecosystem=None) -> Bug:
    """Create OSV entry from errata update"""
    osv = Bug()
    if errata_update.id is None:
        raise ValueError('errata update id is not set')
    osv.db_id = errata_update.id
    if errata_update.title is None:
        logging.warning(f'errata update {errata_update.id} has no title')
    osv.summary = errata_update.title
    osv.affected_packages = _assemble_affected_packages(errata_update, ecosystem)
    osv.upstream = _upstream_from_description(errata_update)
    osv.published_date = errata_update.issued
    osv.modified_date = errata_update.updated
    if errata_update.description is None:
        logging.warning(f'errata update {errata_update.id} has no description')
    osv.details = errata_update.description
    for ref in errata_update.references:
        if osv.reference_url_types is not None:
            osv.reference_url_types[ref.href] = _errata_reference_type_to_osv(ref.type)
        else:
            osv.reference_url_types = {ref.href: _errata_reference_type_to_osv(ref.type)}
    return osv


def _assemble_affected_packages(errata_update: ErrataUpdateXMLView, ecosystem: str) -> List:
    """Assemble affected packages from errata update"""
    affected_packages = []
    for collection in errata_update.pkglist:
        name = collection.name
        packages = collection.packages
        for package in packages:
            affected_package = {
                'package': {
                    'ecosystem': f_collection_name_to_ecosystem(name) if ecosystem is None else ecosystem,
                    'name': package.name,
                },
                'ranges': [{
                    'type': 'ECOSYSTEM',
                    'events': [
                        {
                            'type': 'introduced',
                            'value': '0',
                        },
                        {
                            'type': 'fixed',
                            'value': _package_full_version(package),
                        },
                    ]
                }]
            }
            if affected_package in affected_packages:
                continue
            affected_packages.append(affected_package)

    return affected_packages


def f_collection_name_to_ecosystem(name: str) -> str:
    """Get ecosystem from collection name"""
    for collection_name, ecosystem in collection_name_to_ecosystem.items():
        if re.fullmatch(collection_name, name):
            return ecosystem

    raise ValueError(f'collection name {name} is not supported')


def _package_full_version(package: ErrataPackageXMLView) -> str:
    """Get full version of package"""
    if package.epoch != '0':
        return f'{package.epoch}:{package.version}-{package.release}'
    else:
        return f'{package.version}-{package.release}'


def _upstream_from_description(errata_update: ErrataUpdateXMLView) -> List:
    """Get upstreams from description"""
    description = str(errata_update.title or '') + str(errata_update.description or '')
    return re.findall(r'CVE-\d{4}-\d{4,7}', description)


def _errata_reference_type_to_osv(reference_type: str) -> str:
    """
    Convert errata reference type to OSV reference type
    OSV reference types: https://ossf.github.io/osv-schema/#references-field
    """
    if reference_type == 'self' or reference_type == 'rhsa':
        return 'ADVISORY'
    elif reference_type == 'cve' or reference_type == 'bugzilla':
        return 'REPORT'
    else:
        return 'WEB'
