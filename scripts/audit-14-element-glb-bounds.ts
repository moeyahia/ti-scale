import { readFileSync } from "node:fs";
import { resolve } from "node:path";

interface GlbDescriptor {
  readonly accessors?: ReadonlyArray<{
    readonly count?: number;
    readonly min?: readonly number[];
    readonly max?: readonly number[];
  }>;
  readonly meshes?: ReadonlyArray<{
    readonly primitives?: ReadonlyArray<{
      readonly attributes?: { readonly POSITION?: number };
      readonly material?: number;
      readonly mode?: number;
    }>;
  }>;
  readonly materials?: ReadonlyArray<Record<string, unknown>>;
  readonly nodes?: ReadonlyArray<Record<string, unknown>>;
  readonly scenes?: ReadonlyArray<Record<string, unknown>>;
  readonly scene?: number;
}

interface ReviewManifest {
  readonly models: ReadonlyArray<{
    readonly number: number;
    readonly id: string;
    readonly path: string;
    readonly canonicalization: {
      readonly rootOffset: { readonly x: number; readonly y: number; readonly z: number };
      readonly uniformScale: number;
    };
    readonly assembly: {
      readonly position: { readonly x: number; readonly y: number; readonly z: number };
    };
  }>;
}

function descriptor(path: string): GlbDescriptor {
  const bytes = readFileSync(path);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const jsonLength = view.getUint32(12, true);
  const json = new TextDecoder().decode(bytes.subarray(20, 20 + jsonLength)).replace(/[\u0000\u0020]+$/u, "");
  return JSON.parse(json) as GlbDescriptor;
}

const root = process.cwd();
const manifestPath = resolve(root, "public/review-assets/ti-scale-14-elements/v1/assembly-manifest.json");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as ReviewManifest;

for (const model of manifest.models) {
  const gltf = descriptor(resolve(root, "public", model.path));
  const positions = (gltf.meshes ?? []).flatMap((mesh) => mesh.primitives ?? []).map((primitive) => {
    const accessorIndex = primitive.attributes?.POSITION;
    const accessor = accessorIndex === undefined ? undefined : gltf.accessors?.[accessorIndex];
    return {
      mode: primitive.mode ?? 4,
      count: accessor?.count,
      min: accessor?.min,
      max: accessor?.max,
      material: primitive.material,
    };
  });
  console.log(JSON.stringify({
    number: model.number,
    id: model.id,
    canonicalization: model.canonicalization,
    assemblyPosition: model.assembly.position,
    positions,
    nodes: gltf.nodes,
    scene: gltf.scene,
    scenes: gltf.scenes,
    materials: gltf.materials,
  }));
}
