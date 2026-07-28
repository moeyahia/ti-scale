import { useEffect, useRef } from "react";
import {
  BufferAttribute,
  BufferGeometry,
  Color,
  Group,
  NormalBlending,
  PerspectiveCamera,
  Points,
  Scene,
  ShaderMaterial,
  SRGBColorSpace,
  Vector2,
  WebGLRenderer,
} from "three";
import {
  createParticleCoreGeometry,
  PARTICLE_CORE_CLUSTER_COUNT,
} from "./particleCoreGeometry";
import { createParticleModuleTargets } from "./particleModuleGeometry";
import "./particle-core-runtime.css";

export type ParticleCoreCommandType = "reset" | "rotate-left" | "rotate-right" | "zoom-in" | "zoom-out";

export interface ParticleCoreCommand {
  readonly sequence: number;
  readonly type: ParticleCoreCommandType;
}

export interface ParticleCoreStats {
  readonly pointCount: number;
  readonly clusterCount: number;
  readonly drawCalls: number;
  readonly generationMilliseconds: number;
  readonly renderer: string;
}

export interface ParticleCoreRuntimeProps {
  readonly progress: number;
  readonly moduleProgress?: number;
  readonly selectedCluster?: number;
  readonly reducedMotion: boolean;
  readonly autoRotate: boolean;
  readonly command: ParticleCoreCommand;
  readonly ariaLabel?: string;
  readonly className?: string;
  readonly hoverEnabled?: boolean;
  readonly onReady: (stats: ParticleCoreStats) => void;
  readonly onError: (message: string) => void;
}

interface RuntimeState {
  readonly host: HTMLDivElement;
  readonly renderer: WebGLRenderer;
  readonly camera: PerspectiveCamera;
  readonly scene: Scene;
  readonly sculpture: Group;
  readonly material: ShaderMaterial;
  readonly geometry: BufferGeometry;
  readonly points: Points<BufferGeometry, ShaderMaterial>;
  readonly resizeObserver: ResizeObserver;
  targetProgress: number;
  renderedProgress: number;
  targetModuleProgress: number;
  renderedModuleProgress: number;
  selectedCluster: number;
  reducedMotion: boolean;
  autoRotate: boolean;
  yaw: number;
  pitch: number;
  distance: number;
  hoverX: number;
  hoverY: number;
  hoverTargetX: number;
  hoverTargetY: number;
  hoverStrength: number;
  hoverTargetStrength: number;
  hoverEnabled: boolean;
  frame: number;
  lastFrameAt: number;
  disposed: boolean;
}

const VERTEX_SHADER = /* glsl */`
  attribute vec3 aExplode;
  attribute float aCluster;
  attribute float aPointSize;
  attribute float aTone;
  attribute float aSeed;
  attribute vec3 aModuleTarget;

  uniform float uTime;
  uniform float uExplosion;
  uniform float uModuleProgress;
  uniform float uPixelRatio;
  uniform float uSelectedCluster;
  uniform float uMotion;
  uniform vec2 uPointer;
  uniform float uHover;
  uniform float uViewportAspect;

  varying float vTone;
  varying float vSeed;
  varying float vSelected;
  varying float vDepth;
  varying float vSpecular;

  float easeMechanical(float value) {
    value = clamp(value, 0.0, 1.0);
    return value * value * (3.0 - 2.0 * value);
  }

  void main() {
    float delay = (aCluster / 13.0) * 0.17;
    float clusterProgress = easeMechanical((uExplosion - delay) / max(0.001, 1.0 - delay));
    vec3 transformed = position;
    transformed += aExplode * clusterProgress * (1.62 + aSeed * 0.72);
    transformed += normal * clusterProgress * (0.16 + aSeed * 0.18);

    float pulse = sin(uTime * 0.66 + aSeed * 22.0 + aCluster * 0.37);
    transformed += normal * pulse * 0.017 * uMotion * (1.0 - clusterProgress * 0.72);
    transformed += aExplode * sin(uTime * 0.31 + aSeed * 12.0) * 0.012 * uMotion;

    float moduleProgress = easeMechanical(uModuleProgress);
    transformed = mix(transformed, aModuleTarget, moduleProgress);

    vec4 viewPosition = modelViewMatrix * vec4(transformed, 1.0);
    vec4 projectedPosition = projectionMatrix * viewPosition;
    vec2 projectedPoint = projectedPosition.xy / max(0.001, projectedPosition.w);
    vec2 hoverDelta = projectedPoint - uPointer;
    vec2 hoverMetric = vec2(hoverDelta.x * uViewportAspect, hoverDelta.y);
    float hoverDistance = length(hoverMetric);
    float hoverField = pow(1.0 - smoothstep(0.055, 0.48, hoverDistance), 2.0) * uHover * uMotion;
    vec2 hoverDirection = hoverDistance > 0.0001
      ? normalize(hoverDelta)
      : normalize(vec2(cos(aSeed * 31.0), sin(aSeed * 31.0)));
    float hoverDepthScale = clamp(-viewPosition.z / 8.0, 0.72, 1.28);
    viewPosition.xy += hoverDirection * hoverField * (0.14 + aSeed * 0.075) * hoverDepthScale;
    gl_Position = projectionMatrix * viewPosition;
    float perspective = clamp(10.0 / max(1.0, -viewPosition.z), 0.72, 2.2);
    gl_PointSize = aPointSize * uPixelRatio * perspective;

    vTone = aTone;
    vSeed = aSeed;
    vDepth = clamp((-viewPosition.z - 4.0) / 8.0, 0.0, 1.0);
    vSelected = uSelectedCluster < -0.5 || abs(aCluster - uSelectedCluster) < 0.25 ? 1.0 : 0.0;
    vec3 movingLight = normalize(vec3(cos(uTime * 0.17), 0.52, sin(uTime * 0.17) + 0.62));
    vSpecular = pow(max(0.0, dot(normal, movingLight)), 7.0);
  }
`;

const FRAGMENT_SHADER = /* glsl */`
  precision highp float;

  varying float vTone;
  varying float vSeed;
  varying float vSelected;
  varying float vDepth;
  varying float vSpecular;

  void main() {
    vec2 point = gl_PointCoord - 0.5;
    float angle = (vSeed - 0.5) * 0.72;
    mat2 rotation = mat2(cos(angle), -sin(angle), sin(angle), cos(angle));
    point = rotation * point;
    float distanceToEdge = max(abs(point.x), abs(point.y));
    float alpha = 1.0 - smoothstep(0.36, 0.5, distanceToEdge);
    if (alpha <= 0.002) discard;

    vec3 graphite = vec3(0.035, 0.043, 0.052);
    vec3 titanium = vec3(0.49, 0.535, 0.575);
    vec3 highlight = vec3(0.91, 0.925, 0.93);
    vec3 color = mix(graphite, titanium, smoothstep(0.10, 0.72, vTone));
    color = mix(color, highlight, smoothstep(0.72, 0.98, vTone));
    float diagonalSheen = smoothstep(-0.22, 0.42, point.x - point.y);
    color += diagonalSheen * 0.075 * (0.5 + vTone * 0.5);
    color = mix(color, highlight, vSpecular * 0.46);
    color = mix(color, vec3(0.73, 0.79, 0.84), (1.0 - vSelected) * 0.2);

    float selectedAlpha = mix(0.14, 1.0, vSelected);
    float depthAlpha = mix(0.44, 1.0, 1.0 - vDepth);
    gl_FragColor = vec4(color, alpha * selectedAlpha * depthAlpha * 0.96);
  }
`;

function supportsWebgl2(): boolean {
  const canvas = document.createElement("canvas");
  try {
    return Boolean(canvas.getContext("webgl2", {
      alpha: false,
      antialias: true,
      failIfMajorPerformanceCaveat: false,
    }));
  } catch {
    return false;
  } finally {
    canvas.remove();
  }
}

function render(state: RuntimeState): void {
  state.renderer.render(state.scene, state.camera);
  state.host.dataset.progress = state.renderedProgress.toFixed(4);
  state.host.dataset.moduleProgress = state.renderedModuleProgress.toFixed(4);
  state.host.dataset.cameraYaw = state.yaw.toFixed(4);
  state.host.dataset.cameraPitch = state.pitch.toFixed(4);
  state.host.dataset.cameraDistance = state.distance.toFixed(3);
  state.host.dataset.hoverFieldX = state.hoverX.toFixed(4);
  state.host.dataset.hoverFieldY = state.hoverY.toFixed(4);
  state.host.dataset.hoverStrength = state.hoverStrength.toFixed(4);
  state.host.dataset.hoverActive = state.hoverStrength > 0.02 ? "true" : "false";
}

function applyCamera(state: RuntimeState): void {
  state.sculpture.rotation.set(
    state.pitch - state.hoverY * 0.055,
    state.yaw + state.hoverX * 0.08,
    -0.025 + state.hoverX * 0.008,
  );
  state.camera.position.set(0, 0, state.distance);
  state.camera.lookAt(0, 0, 0);
  state.camera.updateMatrixWorld(true);
  render(state);
}

function scheduleFrame(state: RuntimeState): void {
  if (state.disposed || state.frame) return;
  state.frame = requestAnimationFrame((now) => {
    state.frame = 0;
    if (state.disposed) return;
    const delta = Math.min(0.05, Math.max(0, (now - state.lastFrameAt) / 1_000));
    state.lastFrameAt = now;
    const visible = document.visibilityState === "visible";
    const motionEnabled = !state.reducedMotion && visible;
    state.host.dataset.animationState = visible
      ? state.reducedMotion ? "settled-reduced-motion" : "running"
      : "paused-hidden";
    if (!visible) {
      state.material.uniforms.uMotion!.value = 0;
      render(state);
      return;
    }
    const progressDelta = state.targetProgress - state.renderedProgress;
    if (state.reducedMotion || Math.abs(progressDelta) < 0.0005) state.renderedProgress = state.targetProgress;
    else state.renderedProgress += progressDelta * Math.min(1, delta * 8.4);
    const moduleProgressDelta = state.targetModuleProgress - state.renderedModuleProgress;
    if (state.reducedMotion || Math.abs(moduleProgressDelta) < 0.0005) {
      state.renderedModuleProgress = state.targetModuleProgress;
    } else {
      state.renderedModuleProgress += moduleProgressDelta * Math.min(1, delta * 7.4);
    }
    state.material.uniforms.uExplosion!.value = state.renderedProgress;
    state.material.uniforms.uModuleProgress!.value = state.renderedModuleProgress;
    state.material.uniforms.uTime!.value = now / 1_000;
    state.material.uniforms.uMotion!.value = motionEnabled ? 1 : 0;
    const hoverEase = Math.min(1, delta * 12.5);
    if (state.reducedMotion || !state.hoverEnabled) {
      state.hoverX = 0;
      state.hoverY = 0;
      state.hoverStrength = 0;
    } else {
      state.hoverX += (state.hoverTargetX - state.hoverX) * hoverEase;
      state.hoverY += (state.hoverTargetY - state.hoverY) * hoverEase;
      state.hoverStrength += (state.hoverTargetStrength - state.hoverStrength) * hoverEase;
    }
    state.material.uniforms.uPointer!.value.set(state.hoverX, state.hoverY);
    state.material.uniforms.uHover!.value = state.hoverStrength;
    if (motionEnabled && state.autoRotate) {
      state.yaw += delta * 0.105;
    }
    state.sculpture.rotation.set(
      state.pitch - state.hoverY * 0.055,
      state.yaw + state.hoverX * 0.08,
      -0.025 + state.hoverX * 0.008,
    );
    render(state);
    if (
      motionEnabled
      || Math.abs(state.targetProgress - state.renderedProgress) >= 0.0005
      || Math.abs(state.targetModuleProgress - state.renderedModuleProgress) >= 0.0005
    ) scheduleFrame(state);
  });
}

export default function ParticleCoreRuntime({
  progress,
  moduleProgress = 0,
  selectedCluster,
  reducedMotion,
  autoRotate,
  command,
  ariaLabel = "Interactive titanium particle-shell sculpture with fourteen separable clusters",
  className,
  hoverEnabled = true,
  onReady,
  onError,
}: ParticleCoreRuntimeProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const stateRef = useRef<RuntimeState | undefined>(undefined);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    if (!supportsWebgl2()) {
      onError("WebGL 2 is unavailable. The complete 14-cluster description remains available in the accessible fallback.");
      return;
    }
    const startedAt = performance.now();
    let state: RuntimeState | undefined;
    try {
      const data = createParticleCoreGeometry();
      const moduleTargets = createParticleModuleTargets(data.clusterIds, data.seeds);
      if (data.clusterPointCounts.some((count) => count <= 0)) throw new Error("The procedural sculpture did not populate all fourteen clusters.");
      const geometry = new BufferGeometry();
      geometry.setAttribute("position", new BufferAttribute(data.positions, 3));
      geometry.setAttribute("normal", new BufferAttribute(data.normals, 3));
      geometry.setAttribute("aExplode", new BufferAttribute(data.explodeDirections, 3));
      geometry.setAttribute("aCluster", new BufferAttribute(data.clusterIds, 1));
      geometry.setAttribute("aPointSize", new BufferAttribute(data.pointSizes, 1));
      geometry.setAttribute("aTone", new BufferAttribute(data.tones, 1));
      geometry.setAttribute("aSeed", new BufferAttribute(data.seeds, 1));
      geometry.setAttribute("aModuleTarget", new BufferAttribute(moduleTargets.positions, 3));
      geometry.computeBoundingSphere();

      const renderer = new WebGLRenderer({
        antialias: true,
        alpha: true,
        powerPreference: "high-performance",
      });
      renderer.setClearColor(new Color("#f3f1ed"), 0);
      renderer.setPixelRatio(Math.min(devicePixelRatio, 1.75));
      renderer.outputColorSpace = SRGBColorSpace;
      renderer.domElement.className = "particle-core-runtime__canvas";
      renderer.domElement.tabIndex = 0;
      renderer.domElement.setAttribute("role", "application");
      renderer.domElement.setAttribute("aria-label", ariaLabel);
      host.append(renderer.domElement);

      const material = new ShaderMaterial({
        vertexShader: VERTEX_SHADER,
        fragmentShader: FRAGMENT_SHADER,
        transparent: true,
        depthWrite: false,
        depthTest: true,
        blending: NormalBlending,
        uniforms: {
          uTime: { value: 0 },
          uExplosion: { value: Math.max(0, Math.min(1, progress)) },
          uModuleProgress: { value: Math.max(0, Math.min(1, moduleProgress)) },
          uPixelRatio: { value: Math.min(devicePixelRatio, 1.75) },
          uSelectedCluster: { value: selectedCluster ?? -1 },
          uMotion: { value: reducedMotion ? 0 : 1 },
          uPointer: { value: new Vector2(0, 0) },
          uHover: { value: 0 },
          uViewportAspect: { value: 1 },
        },
      });
      const points = new Points(geometry, material);
      points.frustumCulled = false;
      points.name = "TI_SCALE_PARTICLE_CORE_14_CLUSTER_SCULPTURE";
      const sculpture = new Group();
      sculpture.name = "TI_SCALE_PARTICLE_CORE_STAGE";
      sculpture.rotation.set(-0.035, -0.08, -0.025);
      sculpture.add(points);
      const scene = new Scene();
      scene.add(sculpture);
      const camera = new PerspectiveCamera(37, 1, 0.1, 40);
      camera.position.set(0, 0, 8.3);
      camera.lookAt(0, 0, 0);

      const resizeObserver = new ResizeObserver(() => {
        if (!state) return;
        const width = Math.max(1, host.clientWidth);
        const height = Math.max(1, host.clientHeight);
        renderer.setSize(width, height, false);
        camera.aspect = width / height;
        camera.updateProjectionMatrix();
        material.uniforms.uViewportAspect!.value = width / height;
        render(state);
      });
      state = {
        host,
        renderer,
        camera,
        scene,
        sculpture,
        material,
        geometry,
        points,
        resizeObserver,
        targetProgress: Math.max(0, Math.min(1, progress)),
        renderedProgress: Math.max(0, Math.min(1, progress)),
        targetModuleProgress: Math.max(0, Math.min(1, moduleProgress)),
        renderedModuleProgress: Math.max(0, Math.min(1, moduleProgress)),
        selectedCluster: selectedCluster ?? -1,
        reducedMotion,
        autoRotate,
        yaw: -0.08,
        pitch: -0.035,
        distance: 8.3,
        hoverX: 0,
        hoverY: 0,
        hoverTargetX: 0,
        hoverTargetY: 0,
        hoverStrength: 0,
        hoverTargetStrength: 0,
        hoverEnabled,
        frame: 0,
        lastFrameAt: performance.now(),
        disposed: false,
      };
      stateRef.current = state;
      host.dataset.runtimeReady = "true";
      host.dataset.pointCount = String(data.pointCount);
      host.dataset.clusterCount = String(PARTICLE_CORE_CLUSTER_COUNT);
      host.dataset.clusterPointCounts = data.clusterPointCounts.join(",");
      host.dataset.selectedCluster = String(selectedCluster ?? -1);
      host.dataset.hoverEnabled = hoverEnabled ? "true" : "false";
      host.dataset.hoverActive = "false";
      host.dataset.moduleProgress = String(Math.max(0, Math.min(1, moduleProgress)));
      host.dataset.moduleTargetCount = String(PARTICLE_CORE_CLUSTER_COUNT);
      host.dataset.animationState = document.visibilityState === "visible"
        ? reducedMotion ? "settled-reduced-motion" : "running"
        : "paused-hidden";

      resizeObserver.observe(host);
      const width = Math.max(1, host.clientWidth);
      const height = Math.max(1, host.clientHeight);
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      camera.updateProjectionMatrix();
      material.uniforms.uViewportAspect!.value = width / height;
      render(state);
      const drawCalls = renderer.info.render.calls;
      host.dataset.drawCalls = String(drawCalls);
      const gl = renderer.getContext();
      const rendererName = String(gl.getParameter(gl.RENDERER) ?? "WebGL 2");
      onReady({
        pointCount: data.pointCount,
        clusterCount: PARTICLE_CORE_CLUSTER_COUNT,
        drawCalls,
        generationMilliseconds: Math.round(performance.now() - startedAt),
        renderer: rendererName,
      });

      let pointer: { readonly id: number; readonly origin: Vector2; readonly yaw: number; readonly pitch: number } | undefined;
      const onPointerDown = (event: PointerEvent) => {
        if (!state) return;
        pointer = { id: event.pointerId, origin: new Vector2(event.clientX, event.clientY), yaw: state.yaw, pitch: state.pitch };
        state.hoverTargetStrength = 0;
        renderer.domElement.setPointerCapture(event.pointerId);
      };
      const onPointerMove = (event: PointerEvent) => {
        if (!state) return;
        if (state.hoverEnabled && !state.reducedMotion && event.pointerType !== "touch") {
          const bounds = renderer.domElement.getBoundingClientRect();
          state.hoverTargetX = Math.max(-1, Math.min(1, ((event.clientX - bounds.left) / Math.max(1, bounds.width)) * 2 - 1));
          state.hoverTargetY = Math.max(-1, Math.min(1, -(((event.clientY - bounds.top) / Math.max(1, bounds.height)) * 2 - 1)));
          state.hoverTargetStrength = pointer ? 0 : 1;
        }
        if (pointer?.id === event.pointerId) {
          state.yaw = pointer.yaw + (event.clientX - pointer.origin.x) * 0.0055;
          state.pitch = Math.max(-0.8, Math.min(0.8, pointer.pitch + (event.clientY - pointer.origin.y) * 0.0046));
          applyCamera(state);
        }
        scheduleFrame(state);
      };
      const onPointerUp = (event: PointerEvent) => {
        if (pointer?.id === event.pointerId) {
          pointer = undefined;
          if (state && state.hoverEnabled && !state.reducedMotion && event.pointerType !== "touch") {
            const bounds = renderer.domElement.getBoundingClientRect();
            const remainsInside = event.clientX >= bounds.left && event.clientX <= bounds.right
              && event.clientY >= bounds.top && event.clientY <= bounds.bottom;
            state.hoverTargetStrength = remainsInside ? 1 : 0;
            if (!remainsInside) {
              state.hoverTargetX = 0;
              state.hoverTargetY = 0;
            }
            scheduleFrame(state);
          }
        }
      };
      const onPointerLeave = () => {
        if (!state || pointer) return;
        state.hoverTargetX = 0;
        state.hoverTargetY = 0;
        state.hoverTargetStrength = 0;
        scheduleFrame(state);
      };
      const onPointerCancel = () => {
        pointer = undefined;
        if (!state) return;
        state.hoverTargetX = 0;
        state.hoverTargetY = 0;
        state.hoverTargetStrength = 0;
        scheduleFrame(state);
      };
      const onWheel = (event: WheelEvent) => {
        if (!state) return;
        event.preventDefault();
        state.distance = Math.max(6.1, Math.min(12.8, state.distance + event.deltaY * 0.006));
        applyCamera(state);
      };
      const onKeyDown = (event: KeyboardEvent) => {
        if (!state) return;
        if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
          event.preventDefault();
          state.yaw += event.key === "ArrowLeft" ? -0.16 : 0.16;
        } else if (event.key === "+" || event.key === "=") {
          event.preventDefault();
          state.distance = Math.max(6.1, state.distance - 0.65);
        } else if (event.key === "-") {
          event.preventDefault();
          state.distance = Math.min(12.8, state.distance + 0.65);
        } else if (event.key === "Home") {
          event.preventDefault();
          state.yaw = -0.08;
          state.pitch = -0.035;
          state.distance = 8.3;
        } else return;
        applyCamera(state);
        scheduleFrame(state);
      };
      const onVisibility = () => {
        if (!state) return;
        state.lastFrameAt = performance.now();
        scheduleFrame(state);
      };
      renderer.domElement.addEventListener("pointerdown", onPointerDown);
      renderer.domElement.addEventListener("pointermove", onPointerMove);
      renderer.domElement.addEventListener("pointerup", onPointerUp);
      renderer.domElement.addEventListener("pointercancel", onPointerCancel);
      renderer.domElement.addEventListener("pointerleave", onPointerLeave);
      renderer.domElement.addEventListener("wheel", onWheel, { passive: false });
      renderer.domElement.addEventListener("keydown", onKeyDown);
      document.addEventListener("visibilitychange", onVisibility);
      scheduleFrame(state);

      return () => {
        if (!state) return;
        state.disposed = true;
        if (state.frame) cancelAnimationFrame(state.frame);
        resizeObserver.disconnect();
        document.removeEventListener("visibilitychange", onVisibility);
        renderer.domElement.removeEventListener("pointerdown", onPointerDown);
        renderer.domElement.removeEventListener("pointermove", onPointerMove);
        renderer.domElement.removeEventListener("pointerup", onPointerUp);
        renderer.domElement.removeEventListener("pointercancel", onPointerCancel);
        renderer.domElement.removeEventListener("pointerleave", onPointerLeave);
        renderer.domElement.removeEventListener("wheel", onWheel);
        renderer.domElement.removeEventListener("keydown", onKeyDown);
        sculpture.clear();
        geometry.dispose();
        material.dispose();
        renderer.dispose();
        renderer.forceContextLoss();
        renderer.domElement.remove();
        stateRef.current = undefined;
      };
    } catch (error) {
      state?.resizeObserver.disconnect();
      state?.geometry.dispose();
      state?.material.dispose();
      state?.renderer.dispose();
      onError(error instanceof Error ? error.message : "The particle sculpture could not be created.");
      return;
    }
  // The procedural scene is created once; focused effects update its state.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const state = stateRef.current;
    if (!state) return;
    state.targetProgress = Math.max(0, Math.min(1, progress));
    if (reducedMotion) state.renderedProgress = state.targetProgress;
    scheduleFrame(state);
  }, [progress, reducedMotion]);

  useEffect(() => {
    const state = stateRef.current;
    if (!state) return;
    state.targetModuleProgress = Math.max(0, Math.min(1, moduleProgress));
    if (reducedMotion) state.renderedModuleProgress = state.targetModuleProgress;
    scheduleFrame(state);
  }, [moduleProgress, reducedMotion]);

  useEffect(() => {
    const state = stateRef.current;
    if (!state) return;
    state.selectedCluster = selectedCluster ?? -1;
    state.material.uniforms.uSelectedCluster!.value = state.selectedCluster;
    state.host.dataset.selectedCluster = String(state.selectedCluster);
    render(state);
  }, [selectedCluster]);

  useEffect(() => {
    const state = stateRef.current;
    if (!state) return;
    state.reducedMotion = reducedMotion;
    state.autoRotate = autoRotate;
    if (reducedMotion) {
      state.hoverTargetX = 0;
      state.hoverTargetY = 0;
      state.hoverTargetStrength = 0;
    }
    state.material.uniforms.uMotion!.value = reducedMotion ? 0 : 1;
    scheduleFrame(state);
  }, [autoRotate, reducedMotion]);

  useEffect(() => {
    const state = stateRef.current;
    if (!state) return;
    state.hoverEnabled = hoverEnabled;
    state.host.dataset.hoverEnabled = hoverEnabled ? "true" : "false";
    if (!hoverEnabled) {
      state.hoverTargetX = 0;
      state.hoverTargetY = 0;
      state.hoverTargetStrength = 0;
    }
    scheduleFrame(state);
  }, [hoverEnabled]);

  useEffect(() => {
    const state = stateRef.current;
    if (!state) return;
    state.renderer.domElement.setAttribute("aria-label", ariaLabel);
  }, [ariaLabel]);

  useEffect(() => {
    const state = stateRef.current;
    if (!state || command.sequence === 0) return;
    if (command.type === "reset") {
      state.yaw = -0.08;
      state.pitch = -0.035;
      state.distance = 8.3;
    } else if (command.type === "rotate-left") state.yaw -= 0.2;
    else if (command.type === "rotate-right") state.yaw += 0.2;
    else if (command.type === "zoom-in") state.distance = Math.max(6.1, state.distance - 0.7);
    else if (command.type === "zoom-out") state.distance = Math.min(12.8, state.distance + 0.7);
    applyCamera(state);
    scheduleFrame(state);
  }, [command]);

  return (
    <div
      ref={hostRef}
      className={["particle-core-runtime", className].filter(Boolean).join(" ")}
      data-reduced-motion={reducedMotion ? "true" : "false"}
      data-auto-rotate={autoRotate ? "true" : "false"}
    />
  );
}
