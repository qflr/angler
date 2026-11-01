// The landing anglerfish, cut into three layers from one image so parts can move:
// body (static), lower jaw (snaps around the mouth corner) and lure (swings on its stalk).
// Coordinates are pixels of /angler-fish.png (588 x 308).

const SRC = '/angler-fish.png?v=4';
const W = 588;
const H = 308;

// Lower jaw: traced along the dark gap between the upper and lower teeth, back to the
// mouth corner, then straight down through the solid chin.
const JAW = '20,152 95,154 101,160 108,184 117,187 128,170 135,170 160,190 182,201 179,262 20,262';
// What the body leaves out for the jaw. Its back edge stops short of the jaw's so the two
// overlap through the chin and no seam opens when the jaw rotates.
const JAW_HOLE = '20,152 95,154 101,160 108,184 117,187 128,170 135,170 160,190 172,196 168,262 20,262';
// Lure: stalk and bulb, everything just above the head's upper-left contour (4px clear of it).
const LURE = '-1,-1 215,-1 215,52 201,61 190,66 165,75 150,78 120,105 100,134 85,150 -1,150';

const BODY = `M-1 -1H${W + 1}V${H + 1}H-1Z M${JAW_HOLE.replace(/ /g, ' L')}Z M${LURE.replace(/ /g, ' L')}Z`;

export function AnglerFish({ className }: { className?: string }) {
  const img = <image href={SRC} width={W} height={H} />;
  return (
    <svg className={className} viewBox={`0 0 ${W} ${H}`} aria-hidden focusable="false">
      <defs>
        <clipPath id="fish-body">
          <path d={BODY} clipRule="evenodd" />
        </clipPath>
        <clipPath id="fish-jaw">
          <polygon points={JAW} />
        </clipPath>
        <clipPath id="fish-lure">
          <polygon points={LURE} />
        </clipPath>
      </defs>
      <g clipPath="url(#fish-body)">{img}</g>
      <g className="fish-lure">
        <g clipPath="url(#fish-lure)">{img}</g>
      </g>
      <g className="fish-jaw">
        <g clipPath="url(#fish-jaw)">{img}</g>
      </g>
    </svg>
  );
}
