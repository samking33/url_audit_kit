'use client';

import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet';
import type { ThreatMapPoint } from '@/types';

interface LeafletThreatMapProps {
  points: ThreatMapPoint[];
}

function markerRadius(count: number): number {
  return Math.max(8, Math.min(22, 8 + count * 1.2));
}

export default function LeafletThreatMap({ points }: LeafletThreatMapProps) {
  const center: [number, number] = points.length
    ? [points[0].lat, points[0].lng]
    : [20, 0];
  const zoom = points.length === 1 ? 3 : 2;

  return (
    <div className="leaflet-threat-map">
      <MapContainer center={center} zoom={zoom} scrollWheelZoom className="leaflet-map-canvas">
        <TileLayer
          attribution='&copy; OpenStreetMap contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        />
        {points.map((point) => (
          <CircleMarker
            key={`${point.country}-${point.lat}-${point.lng}`}
            center={[point.lat, point.lng]}
            radius={markerRadius(point.count)}
            pathOptions={{
              color: '#b42318',
              weight: 2,
              fillColor: '#f04438',
              fillOpacity: 0.45,
            }}
          >
            <Popup>
              <strong>{point.country}</strong>
              <div>{point.count} indicators</div>
              <div>Critical: {point.critical}</div>
              <div>High: {point.high}</div>
              <div>Medium: {point.medium}</div>
              <div>Low: {point.low}</div>
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  );
}
