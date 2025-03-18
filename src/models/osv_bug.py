import copy
import datetime
import json
from typing import List

import osv


class OSVBugJsonView():
    def __init__(self, bug: osv.Bug):
        self.db_id = bug.db_id
        self.summary = bug.summary
        self.affected_packages = sorted(copy.deepcopy(bug.affected_packages),
                                        key=lambda affected: affected.package.name)
        self.related = copy.deepcopy(bug.related)
        self.upstream = copy.deepcopy(bug.upstream)
        self.published = bug.published_date
        self.modified = bug.modified_date
        self.details = bug.details
        self.references = copy.deepcopy(bug.reference_url_types)

    def to_json_file(self, filename: str):
        with open(filename, 'w') as f:
            f.write(self.to_json_str())

    def to_json_str(self) -> str:
        return json.dumps({
            'id': self.db_id,
            'summary': self.summary,
            'affected': self.affected_format_list(),
            'upstream': self.upstream,
            'published': self.published_format_str(),
            'modified': self.modified_format_str(),
            'details': self.details,
            'references': self.references_format_list(),
        }, indent=2)

    def affected_format_list(self) -> List[dict]:
        return [
            {
                'package': self._package_format_dict(affected.package),
                'ranges': self._ranges_format_list(affected.ranges),
            } for affected in self.affected_packages
        ]

    def _package_format_dict(self, package: osv.AffectedPackage) -> dict:
        return {
            'ecosystem': package.ecosystem,
            'name': package.name,
        }

    def _ranges_format_list(self, ranges: List[osv.AffectedRange2]) -> List[dict]:
        return [
            {
                'type': _range.type,
                'events': self._events_format_list(_range.events),
            } for _range in ranges
        ]

    def _events_format_list(self, events: List[osv.AffectedEvent]) -> List[dict]:
        return [
            {
                event.type: event.value,
            } for event in events
        ]

    def _timestamp_format_str(self, timestamp: datetime.datetime) -> str:
        return timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')

    def published_format_str(self) -> str:
        return self._timestamp_format_str(self.published)

    def modified_format_str(self) -> str:
        return self._timestamp_format_str(self.modified)

    def references_format_list(self) -> List[dict]:
        if self.references is None:
            return []

        return [
            {
                'url': url,
                'type': url_type
            } for url, url_type in sorted(self.references.items())
        ]
