; ModuleID = 'bpftrace'
source_filename = "bpftrace"
target datalayout = \"e-m:e-p:64:64-i64:64-i128:128-n32:64-S128\"
target triple = \"bpf-pc-linux\"

%bpf_pidns_info = type { i32, i32 }

; Function Attrs: nounwind
 declare i64 @llvm.bpf.pseudo(i64 %0, i64 %1) #0

define i64 @\"kprobe:f\"(i8* %0) section \"s_kprobe:f_1\" !dbg !4 {
entry:
  %\"@y_val\" = alloca i64, align 8
  %\"@y_key\" = alloca i64, align 8
  %bpf_pidns_info1 = alloca %bpf_pidns_info, align 8
  %\"@x_val\" = alloca i64, align 8
  %\"@x_key\" = alloca i64, align 8
  %bpf_pidns_info = alloca %bpf_pidns_info, align 8
  call void @llvm.lifetime.start.p0(i64 -1, ptr %bpf_pidns_info)
  %get_ns_pid_tgid = call i64 inttoptr (i64 120 to ptr)(i64 0, i64 4026531857, ptr %bpf_pidns_info, i32 8)
  %1 = getelementptr %bpf_pidns_info, ptr %bpf_pidns_info, i32 0, i32 0
  %2 = load i32, ptr %1, align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %bpf_pidns_info)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %\"@x_key\")
  store i64 0, ptr %\"@x_key\", align 8
  %3 = zext i32 %2 to i64
  call void @llvm.lifetime.start.p0(i64 -1, ptr %\"@x_val\")
  store i64 %3, ptr %\"@x_val\", align 8
  %pseudo = call i64 @llvm.bpf.pseudo(i64 1, i64 0)
  %update_elem = call i64 inttoptr (i64 2 to ptr)(i64 %pseudo, ptr %\"@x_key\", ptr %\"@x_val\", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %\"@x_val\")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %\"@x_key\")
  call void @llvm.lifetime.start.p0(i64 -1, ptr %bpf_pidns_info1)
  %get_ns_pid_tgid2 = call i64 inttoptr (i64 120 to ptr)(i64 0, i64 4026531857, ptr %bpf_pidns_info1, i32 8)
  %4 = getelementptr %bpf_pidns_info, ptr %bpf_pidns_info1, i32 0, i32 1
  %5 = load i32, ptr %4, align 4
  call void @llvm.lifetime.end.p0(i64 -1, ptr %bpf_pidns_info1)
  call void @llvm.lifetime.start.p0(i64 -1, ptr %\"@y_key\")
  store i64 0, ptr %\"@y_key\", align 8
  %6 = zext i32 %5 to i64
  call void @llvm.lifetime.start.p0(i64 -1, ptr %\"@y_val\")
  store i64 %6, ptr %\"@y_val\", align 8
  %pseudo3 = call i64 @llvm.bpf.pseudo(i64 1, i64 1)
  %update_elem4 = call i64 inttoptr (i64 2 to ptr)(i64 %pseudo3, ptr %\"@y_key\", ptr %\"@y_val\", i64 0)
  call void @llvm.lifetime.end.p0(i64 -1, ptr %\"@y_val\")
  call void @llvm.lifetime.end.p0(i64 -1, ptr %\"@y_key\")
  ret i64 0
}

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg %0, i8* nocapture %1) #1

; Function Attrs: argmemonly nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg %0, i8* nocapture %1) #1

attributes #0 = { nounwind }
attributes #1 = { argmemonly nofree nosync nounwind willreturn }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3}

!0 = distinct !DICompileUnit(language: DW_LANG_C, file: !1, producer: \"bpftrace\", isOptimized: false, runtimeVersion: 0, emissionKind: LineTablesOnly, enums: !2)
!1 = !DIFile(filename: \"bpftrace.bpf.o\", directory: \".\")
!2 = !{}
!3 = !{i32 2, !\"Debug Info Version\", i32 3}
!4 = distinct !DISubprogram(name: \"kprobe_f\", linkageName: \"kprobe_f\", scope: !1, file: !1, type: !5, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !10)
!5 = !DISubroutineType(types: !6)
!6 = !{!7, !8}
!7 = !DIBasicType(name: \"int64\", size: 64, encoding: DW_ATE_signed)
!8 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !9, size: 64)
!9 = !DIBasicType(name: \"int8\", size: 8, encoding: DW_ATE_signed)
!10 = !{!11, !12}
!11 = !DILocalVariable(name: \"var0\", scope: !4, file: !1, type: !7)
!12 = !DILocalVariable(name: \"var1\", arg: 1, scope: !4, file: !1, type: !8)\n
