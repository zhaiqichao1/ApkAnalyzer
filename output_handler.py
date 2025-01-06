import os
import json
import openpyxl
from datetime import datetime

class OutputHandler:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
    def save_results(self, results):
        """保存分析结果"""
        try:
            # 生成文件名
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name = os.path.splitext(os.path.basename(results['file_name']))[0]
            
            # 保存JSON结果
            json_name = f"{base_name}_{timestamp}.json"
            json_path = os.path.join(self.output_dir, json_name)
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4, ensure_ascii=False)
                
            # 保存Excel结果
            excel_name = f"{base_name}_{timestamp}.xlsx"
            excel_path = os.path.join(self.output_dir, excel_name)
            self._save_excel(results, excel_path)
            
            print(f"结果已保存到:")
            print(f"JSON: {json_path}")
            print(f"Excel: {excel_path}")
            
        except Exception as e:
            print(f"保存结果时出错: {str(e)}")
            print(f"文件名: {results.get('file_name', 'unknown')}")
            print(f"输出目录: {self.output_dir}")
            raise  # 重新抛出异常以查看完整的错误堆栈
            
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
            print(f"结果数据: {results}")
            
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "网络请求分析"
            
            # 写入标题
            headers = ['域名', 'IP地址', '端口', '时间', '国家', '地区', '城市', 'ISP', '组织']
            for col, header in enumerate(headers, 1):
                ws.cell(row=1, column=col, value=header)
            
            # 写入数据
            requests = results.get('requests', [])
            print(f"请求数量: {len(requests)}")
            
            for row, request in enumerate(requests, 2):
                try:
                    print(f"处理第 {row-1} 个请求: {request}")
                    
                    # 逐个处理每个字段
                    domain = str(request.get('domain', ''))
                    ip = str(request.get('ip', ''))
                    port = str(request.get('port', ''))
                    timestamp = str(request.get('timestamp', ''))
                    country = str(request.get('country', ''))
                    region = str(request.get('region', ''))
                    city = str(request.get('city', ''))
                    isp = str(request.get('isp', ''))
                    org = str(request.get('org', ''))
                    
                    # 写入单元格
                    ws.cell(row=row, column=1, value=domain)
                    ws.cell(row=row, column=2, value=ip)
                    ws.cell(row=row, column=3, value=port)
                    ws.cell(row=row, column=4, value=timestamp)
                    ws.cell(row=row, column=5, value=country)
                    ws.cell(row=row, column=6, value=region)
                    ws.cell(row=row, column=7, value=city)
                    ws.cell(row=row, column=8, value=isp)
                    ws.cell(row=row, column=9, value=org)
                    
                except Exception as e:
                    print(f"处理行 {row} 时出错: {str(e)}")
                    print(f"请求数据: {request}")
                    continue
            
            print("数据写入完成，开始调整列宽...")
            
            # 调整列宽
            try:
                for col in range(1, len(headers) + 1):
                    max_length = 0
                    for row in range(1, ws.max_row + 1):
                        cell = ws.cell(row=row, column=col)
                        try:
                            if cell.value:
                                max_length = max(max_length, len(str(cell.value)))
                        except:
                            pass
                    ws.column_dimensions[ws.cell(row=1, column=col).column_letter].width = max_length + 2
            except Exception as e:
                print(f"调整列宽时出错: {str(e)}")
            
            print(f"准备保存文件到: {excel_path}")
            # 保存文件
            wb.save(excel_path)
            print("Excel文件保存成功")
            
        except Exception as e:
            print(f"保存Excel文件时出错: {str(e)}")
            print(f"Excel路径: {excel_path}")
            if 'request' in locals():
                print(f"当前处理的请求数据: {request}")
            import traceback
            print(f"错误堆栈: {traceback.format_exc()}")
            raise 