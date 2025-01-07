import os
import json
import openpyxl
from datetime import datetime
from urllib.parse import urlparse

class OutputHandler:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
    def save_results(self, results):
        """保存分析结果"""
        try:
            # 获取APK文件名（不含扩展名）
            base_name = os.path.splitext(os.path.basename(results['file_name']))[0]
            
            # 获取当前时间
            timestamp = datetime.now()
            date_str = timestamp.strftime('%Y%m%d')
            time_str = timestamp.strftime('%H%M%S')
            
            # 获取分析信息
            request_count = len(results.get('requests', []))
            domain_count = len(set(req.get('domain', '') for req in results.get('requests', []) if req.get('domain')))
            ip_count = len(set(req.get('ip', '') for req in results.get('requests', []) if req.get('ip') and req.get('ip') != 'Unknown'))
            
            # 构建文件名
            # 格式: APK名称_日期_时间_域名数_IP数_总请求数
            file_prefix = f"{base_name}_{date_str}_{time_str}_域名{domain_count}_IP{ip_count}_请求{request_count}"
            
            # 如果文件名太长，使用简短版本
            if len(file_prefix) > 100:
                # 如果APK名称太长，截取前30个字符
                if len(base_name) > 30:
                    base_name = base_name[:27] + "..."
                file_prefix = f"{base_name}_{date_str}_{time_str}_D{domain_count}_I{ip_count}_R{request_count}"
            
            # 保存JSON结果
            json_path = os.path.join(self.output_dir, f"{file_prefix}.json")
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
            
            # 保存Excel结果
            excel_path = os.path.join(self.output_dir, f"{file_prefix}.xlsx")
            self._save_excel(results, excel_path)
            
            # 打印保存结果
            print("\n分析结果已保存:")
            print(f"文件名: {os.path.basename(excel_path)}")
            print(f"保存位置: {self.output_dir}")
            print("\n分析统计:")
            print(f"域名数量: {domain_count}")
            print(f"IP数量: {ip_count}")
            print(f"总请求数: {request_count}\n")
            
            return {
                'json_path': json_path,
                'excel_path': excel_path,
                'stats': {
                    'domain_count': domain_count,
                    'ip_count': ip_count,
                    'request_count': request_count
                }
            }
            
        except Exception as e:
            print(f"保存结果时出错: {str(e)}")
            print(f"APK文件: {results.get('file_name', 'unknown')}")
            print(f"输出目录: {self.output_dir}")
            raise 

    def _format_timestamp(self, timestamp):
        """格式化时间戳"""
        try:
            if not timestamp:  # 处理空值
                return ''
            
            if isinstance(timestamp, str):
                # 处理ISO格式时间戳
                if 'Z' in timestamp:
                    from datetime import datetime
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    return dt.strftime('%Y-%m-%d %H:%M:%S')
                # 处理Unix时间戳字符串
                elif timestamp.replace('.', '').isdigit():
                    from datetime import datetime
                    try:
                        # 尝试处理毫秒时间戳
                        ts = float(timestamp)
                        if ts > 1e10:  # 假设是毫秒时间戳
                            ts = ts / 1000
                        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        return timestamp
                # 其他字符串格式，直接返回
                return timestamp
            elif isinstance(timestamp, (int, float)):
                # 处理数字类型的时间戳
                from datetime import datetime
                try:
                    if timestamp > 1e10:  # 假设是毫秒时间戳
                        timestamp = timestamp / 1000
                    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                except:
                    return str(timestamp)
            else:
                # 其他类型，转为字符串
                return str(timestamp)
        except Exception as e:
            print(f"格式化时间戳出错: {str(e)}, 时间戳值: {timestamp}, 类型: {type(timestamp)}")
            return str(timestamp)

    def _save_excel(self, results, excel_path):
        """保存为Excel格式"""
        try:
            print("开始保存Excel...")
            
            wb = openpyxl.Workbook()
            
            # 创建基本信息sheet
            ws_info = wb.active
            ws_info.title = "基本信息"
            
            # 写入APK基本信息
            info_headers = ['项目', '值']
            for col, header in enumerate(info_headers, 1):
                cell = ws_info.cell(row=1, column=col)
                cell.value = header
                cell.font = openpyxl.styles.Font(bold=True)
                cell.fill = openpyxl.styles.PatternFill(start_color="E0E0E0", end_color="E0E0E0", fill_type="solid")
            
            info_data = [
                ['APK文件名', results.get('file_name', '')],
                ['文件Hash', results.get('hash', '')],
                ['分析时间', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['网络请求数', len(results.get('requests', []))]
            ]
            
            for row, (item, value) in enumerate(info_data, 2):
                ws_info.cell(row=row, column=1, value=item)
                ws_info.cell(row=row, column=2, value=value)
            
            # 调整基本信息表格列宽
            ws_info.column_dimensions['A'].width = 20
            ws_info.column_dimensions['B'].width = 50
            
            # 创建网络请求sheet
            ws_requests = wb.create_sheet("网络请求详情")
            
            # 写入表头
            headers = [
                '时间', '域名', 'IP地址', '端口', '请求类型',
                '国家', '地区', '城市', 'ISP', '组织',
                'URL', '请求方法', '协议'
            ]
            
            # 设置表头样式
            for col, header in enumerate(headers, 1):
                cell = ws_requests.cell(row=1, column=col)
                cell.value = header
                cell.font = openpyxl.styles.Font(bold=True, color="FFFFFF")
                cell.fill = openpyxl.styles.PatternFill(start_color="366092", end_color="366092", fill_type="solid")
                cell.alignment = openpyxl.styles.Alignment(horizontal="center")
            
            # 写入请求数据
            for row, request in enumerate(results.get('requests', []), 2):
                try:
                    # 处理时间戳
                    timestamp = self._format_timestamp(request.get('timestamp', ''))
                    
                    # 解析URL信息
                    url = request.get('url', '')
                    protocol = ''
                    method = request.get('method', '')
                    if url:
                        try:
                            parsed = urlparse(url)
                            protocol = parsed.scheme
                        except:
                            pass
                    
                    # 写入数据
                    data = [
                        timestamp,
                        request.get('domain', ''),
                        request.get('ip', ''),
                        request.get('port', ''),
                        request.get('type', ''),
                        request.get('country', ''),
                        request.get('region', ''),
                        request.get('city', ''),
                        request.get('isp', ''),
                        request.get('org', ''),
                        url,
                        method,
                        protocol
                    ]
                    
                    for col, value in enumerate(data, 1):
                        cell = ws_requests.cell(row=row, column=col)
                        cell.value = str(value)
                        cell.alignment = openpyxl.styles.Alignment(horizontal="center")
                    
                except Exception as e:
                    print(f"处理第 {row-1} 行数据时出错: {str(e)}")
                    continue
            
            # 设置自动列宽
            for column in ws_requests.columns:
                max_length = 0
                column_letter = openpyxl.utils.get_column_letter(column[0].column)
                
                for cell in column:
                    try:
                        if cell.value:
                            max_length = max(max_length, len(str(cell.value)))
                    except:
                        pass
                
                adjusted_width = min(max_length + 2, 50)  # 最大宽度限制为50
                ws_requests.column_dimensions[column_letter].width = adjusted_width
            
            # 添加筛选器
            ws_requests.auto_filter.ref = ws_requests.dimensions
            
            # 冻结首行
            ws_requests.freeze_panes = 'A2'
            
            # 保存文件
            wb.save(excel_path)
            print("Excel文件保存成功")
            
        except Exception as e:
            print(f"保存Excel文件时出错: {str(e)}")
            if 'request' in locals():
                print(f"当前处理的请求数据: {request}")
            raise 